"""Translate native XMPP friend operations to authenticated shared social state.

No SASL credentials are forwarded. The bridge's existing Worker session owns
every operation; JIDs supply only the *target* of an invitation or request.
"""
from __future__ import annotations
import copy
import hashlib
import re
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

ROSTER='jabber:iq:roster'
SEARCH='jabber:iq:search'
VCARD='vcard-temp'
NICK='http://jabber.org/protocol/nick'
DATA='jabber:x:data'
ID=re.compile(r'[A-Za-z0-9_-]{1,36}\Z')
CHAT_HOST = 'conference.revival-xmpp.localhost'
CHAT_ROOM = re.compile(r'(party|lobby)-([A-Za-z0-9_-]{1,128})@' + re.escape(CHAT_HOST) + r'\Z')

def chat_room_jid(scope, identifier):
    jid = f'{scope}-{identifier}@{CHAT_HOST}'
    if not CHAT_ROOM.fullmatch(jid):
        raise ValueError('invalid_chat_room')
    return jid

def _xml_text(value):
    return isinstance(value,str) and all(
        char in '\t\n\r' or 0x20<=ord(char)<=0xd7ff
        or 0xe000<=ord(char)<=0xfffd or 0x10000<=ord(char)<=0x10ffff
        for char in value)

def _validate_rows(rows):
    # Validate only fields consumed by the native roster/search renderer.
    # Additional Worker metadata and crossed pending requests remain valid.
    if not isinstance(rows,list):raise ValueError('invalid_social_response')
    for row in rows:
        if not isinstance(row,dict) or not isinstance(row.get('id'),str) \
                or not ID.fullmatch(row['id']) or not _xml_text(row.get('displayName')) \
                or ('status' in row and not _xml_text(row['status'])):
            raise ValueError('invalid_social_response')

class NativeSocial:
    def __init__(self, api, user_id, *, trace=None, presence_source=None):
        if not ID.fullmatch(user_id):raise ValueError('invalid_social_identity')
        self.api,self.user_id=api,user_id
        self.trace=trace or (lambda event:None)
        self._native_presence='online'
        self.presence_source=presence_source or (lambda:self._native_presence)
        self._lock=threading.RLock()
        self._snapshot={'friends':[],'incoming':[],'outgoing':[],'recent':[],'party':None,'invitations':[]}
        self._stop=threading.Event();self._thread=None;self._publish=None
        self._search_results=[]
        self._chat_delivery = None
        self._chat_nonce = uuid.uuid4().hex
        self._chat_delivered = []
        self._chat_rooms = {}

    def _room_request(self, jid, action, body):
        match = CHAT_ROOM.fullmatch(jid)
        if not match:
            raise ValueError('invalid_chat_room')
        scope, identifier = match.groups()
        path = '/v1/social/party' + action if scope == 'party' else '/v1/rooms/' + identifier + '/' + action
        return self.api._request('POST', path,
            body={**body, **({'partyId': identifier} if scope == 'party' else {})})

    def room_presence(self, jid, *, leave=False):
        """Authorize current membership before acknowledging a native MUC join."""
        if not CHAT_ROOM.fullmatch(jid):
            raise ValueError('invalid_chat_room')
        if leave:
            with self._lock:
                self._chat_rooms.pop(jid, None)
            return
        response = self._room_request(jid, 'messages', {'after': 0})
        self._validate_messages(response, channel=True)
        with self._lock:
            if jid not in self._chat_rooms and len(self._chat_rooms) >= 4:
                raise ValueError('chat_room_limit')
            self._chat_rooms.setdefault(jid, 0)

    def message(self, element):
        """Send ordinary direct chat using the authenticated bridge identity."""
        if element.get('type') not in (None, 'chat', 'normal', 'groupchat'):
            raise ValueError('unsupported_chat_type')
        bodies = [node for node in element if node.tag in ('body', '{jabber:client}body')]
        if not bodies:
            return  # Composing/active chat-state notifications carry no text.
        if len(bodies) != 1 or len(bodies[0]):
            raise ValueError('invalid_chat_body')
        text = bodies[0].text
        if not _xml_text(text) or not text.strip() or len(text.encode('utf-8')) > 2048:
            raise ValueError('invalid_chat_body')
        stanza_id = element.get('id')
        if stanza_id is not None and (not isinstance(stanza_id, str) or len(stanza_id) > 128):
            raise ValueError('invalid_chat_id')
        request_id = hashlib.sha256((self._chat_nonce + ':' + (stanza_id or uuid.uuid4().hex)).encode()).hexdigest()
        if element.get('type') == 'groupchat':
            target = element.get('to', '').split('/', 1)[0]
            with self._lock:
                if target not in self._chat_rooms:
                    raise ValueError('chat_room_not_joined')
            response = self._room_request(target, 'chat', {'text': text, 'requestId': request_id})
        else:
            target = self.target(element.get('to'))
            response = self.api._request('POST', '/v1/social/chat', body={
                'target': target, 'text': text, 'requestId': request_id})
        if not isinstance(response, dict) or response.get('accepted') is not True:
            raise ValueError('invalid_chat_response')

    @staticmethod
    def _validate_messages(response, *, channel=False):
        rows = response.get('messages') if isinstance(response, dict) else None
        if not isinstance(rows, list) or len(rows) > (100 if channel else 32):
            raise ValueError('invalid_chat_response')
        sequence = 0
        for row in rows:
            if (not isinstance(row, dict) or not isinstance(row.get('id'), str)
                    or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', row['id'])
                    or not isinstance(row.get('senderId'), str) or not ID.fullmatch(row['senderId'])
                    or not _xml_text(row.get('displayName')) or len(row['displayName']) > 128
                    or not _xml_text(row.get('text')) or not row['text'].strip()
                    or len(row['text'].encode('utf-8')) > 2048):
                raise ValueError('invalid_chat_response')
            if channel:
                if type(row.get('sequence')) is not int or not sequence < row['sequence'] < 2**53:
                    raise ValueError('invalid_chat_response')
                sequence = row['sequence']
        return rows

    def poll_messages(self):
        if self._chat_delivery is None:
            return
        response = self.api._request('POST', '/v1/social/messages', body={})
        rows = self._validate_messages(response)
        ids = []
        for row in rows:
            if row['id'] not in self._chat_delivered:
                if self._chat_delivery(copy.deepcopy(row)) is not True:
                    continue
                self._chat_delivered = (self._chat_delivered + [row['id']])[-128:]
            ids.append(row['id'])
        if ids:
            self.api._request('POST', '/v1/social/chatack', body={'ids': ids})

    def poll_rooms(self):
        if self._chat_delivery is None:
            return
        with self._lock:
            rooms = list(self._chat_rooms.items())
        for jid, after in rooms:
            try:
                rows = self._validate_messages(self._room_request(jid, 'messages', {'after': after}), channel=True)
                for row in rows:
                    with self._lock:
                        if jid not in self._chat_rooms:
                            break
                    if row['sequence'] <= after:
                        continue
                    if self._chat_delivery({**row, 'room': jid}) is not True:
                        break
                    with self._lock:
                        if jid in self._chat_rooms:
                            self._chat_rooms[jid] = row['sequence']
            except Exception as error:
                if getattr(error, 'status', None) in (403, 404, 410):
                    with self._lock:
                        self._chat_rooms.pop(jid, None)
                self.trace({'event': 'native_channel_chat_unavailable'})

    def command(self,action,body=None):
        # The action allowlist prevents path/query injection through native data.
        if action not in ('get','heartbeat','search','request','respond','remove','create','invite','join','leave','transfer','settings','ready'):
            raise ValueError('invalid_social_action')
        response=self.api._request('GET' if action=='get' else 'POST',
                                  '/v1/social' if action=='get' else '/v1/social/'+action,
                                  **({} if action=='get' else {'body':body or {}}))
        if not isinstance(response,dict):raise ValueError('invalid_social_response')
        if action=='search':
            _validate_rows(response.get('players'))
        else:
            for key in ('friends','incoming','outgoing','recent'):
                _validate_rows(response.get(key))
        response=copy.deepcopy(response)
        if action!='search':
            revision=response.get('revision')
            if 'revision' in response and (type(revision) is not int or not 0<=revision<2**53):
                raise ValueError('invalid_social_revision')
            with self._lock:
                before=self._snapshot
                previous=before.get('revision')
                if type(previous) is int and 'revision' not in response:
                    raise ValueError('missing_social_revision')
                stale=type(previous) is int and revision is not None and revision<previous
                if not stale:self._snapshot=copy.deepcopy(response)
                if stale and action in ('get','heartbeat'):response=copy.deepcopy(before)
            if stale:
                self.trace({'event':'native_social_stale_snapshot','action':action})
                # Reads must reflect the current cache so an explicit friend
                # action cannot decide from an older pending request. Mutation
                # callers still receive the real API response for that call.
                return response
            if self._publish is not None and before!=response:self._publish(before,response)
        return response

    def snapshot(self):
        with self._lock:return copy.deepcopy(self._snapshot)

    def target(self,jid):
        if not isinstance(jid,str):raise ValueError('invalid_social_target')
        value=jid.split('@',1)[0]
        if not ID.fullmatch(value) or value==self.user_id:raise ValueError('invalid_social_target')
        return value

    def roster_xml(self,host):
        items=[self._roster_item(row,host,subscription)
               for row,subscription in self.roster_entries(self.snapshot()).values()]
        return "<query xmlns='jabber:iq:roster'>"+''.join(items)+'</query>'

    @staticmethod
    def roster_entries(state):
        # Stock represents requests with one-way subscriptions: from=incoming,
        # to=outgoing. Its subscribe callback automatically ACKs with subscribed.
        # That ACK is presence authorization, not an explicit friendship approval.
        entries={}
        for key,subscription in (('outgoing','to'),('incoming','from'),('friends','both')):
            for row in state.get(key,[]):entries[row['id']]=(row,subscription)
        return entries

    @staticmethod
    def _roster_item(row,host,subscription,pending=False):
        if not ID.fullmatch(row['id']):raise ValueError('invalid_friend_id')
        return ('<item jid='+quoteattr(row['id']+'@'+host)+' name='+quoteattr(row['displayName'])+
                ' subscription='+quoteattr(subscription)+(" ask='subscribe'" if pending else '')+'/>' )

    def iq(self,element,host):
        """Return an IQ body, or None when this is not a social operation."""
        kind=element.get('type')
        if kind == 'get' and CHAT_ROOM.fullmatch(element.get('to', '').split('/', 1)[0]):
            if element.find('{http://jabber.org/protocol/disco#info}query') is not None:
                return ('<query xmlns="http://jabber.org/protocol/disco#info">'
                    '<identity category="conference" type="text" name="TWA Chat"/>'
                    '<feature var="http://jabber.org/protocol/muc"/>'
                    '<feature var="muc_membersonly"/></query>')
        query=element.find('{'+ROSTER+'}query')
        if query is not None:
            if kind=='get':return self.roster_xml(host)
            if kind=='set':
                items=list(query)
                if len(items)!=1 or items[0].tag!='{'+ROSTER+'}item':raise ValueError('invalid_roster_mutation')
                item=items[0];target=self.target(item.get('jid'))
                if item.get('subscription')=='remove':self.command('remove',{'target':target})
                # Roster creation alone is not approval: the client's following
                # presence subscribe supplies the request. Nicknames are ignored.
                elif item.get('subscription') not in (None,'none'):raise ValueError('invalid_roster_subscription')
                return ''
        query=element.find('{'+SEARCH+'}query')
        if query is not None:
            if kind=='get':return "<query xmlns='jabber:iq:search'><instructions>Search by player name</instructions><nick/></query>"
            if kind=='set':
                forms=query.findall('{'+DATA+'}x')
                dataform=bool(forms)
                if dataform:
                    if len(forms)!=1 or forms[0].get('type')!='submit':raise ValueError('invalid_friend_search')
                    fields=[node for node in forms[0].findall('{'+DATA+'}field')
                            if node.get('var') in ('search','nick','username','name')]
                    if len(fields)!=1:raise ValueError('invalid_friend_search')
                    values=fields[0].findall('{'+DATA+'}value')
                    if len(values)!=1 or len(values[0]):raise ValueError('invalid_friend_search')
                    text=values[0].text
                else:
                    text=next((node.text for node in query if node.tag.rsplit('}',1)[-1] in ('nick','username','name','search') and node.text),None)
                if not text or not 2<=len(text)<=64:raise ValueError('invalid_friend_search')
                form='dataform' if dataform else 'legacy'
                self.trace({'event':'native_social_search','phase':'received','namespace':SEARCH,
                            'iq_type':'set','request_format':form})
                rows=self.command('search',{'name':text})['players']
                self._search_results=rows
                if dataform:
                    # Stock gloox SearchHandler reads DataForm items with jid/nick.
                    # Its legacy-result callback is empty, so preserve the request format.
                    items=''.join('<item><field var="jid"><value>'+escape(row['id']+'@'+host)+
                                  '</value></field><field var="nick"><value>'+escape(row['displayName'])+
                                  '</value></field></item>' for row in rows)
                    inner=('<x xmlns="jabber:x:data" type="result"><reported>'
                           '<field var="jid" type="jid-single"/><field var="nick" type="text-single"/>'
                           '</reported>'+items+'</x>')
                else:
                    inner=''.join('<item jid='+quoteattr(row['id']+'@'+host)+'><nick>'+escape(row['displayName'])+'</nick><first>'+escape(row['displayName'])+'</first></item>' for row in rows)
                self.trace({'event':'native_social_search','phase':'response','namespace':SEARCH,
                            'iq_type':'result','response_format':form})
                return "<query xmlns='jabber:iq:search'>"+inner+'</query>'
        if element.find('{'+VCARD+'}vCard') is not None and kind=='get':
            if not element.get('to') or element.get('to','').split('@',1)[0]==self.user_id:return None
            target=self.target(element.get('to'))
            rows=[r for name in ('friends','incoming','outgoing','recent') for r in self.snapshot()[name]]+self._search_results
            row=next((r for r in rows if r['id']==target),None)
            if row:return "<vCard xmlns='vcard-temp'><FN>"+escape(row['displayName'])+'</FN><NICKNAME>'+escape(row['displayName'])+'</NICKNAME></vCard>'
        return None

    def presence(self,element):
        kind=element.get('type')
        if kind in (None,'unavailable'):
            status=next((node.text for node in element if node.tag.rsplit('}',1)[-1]=='status'),None)
            states={None:'online','':'online','in_mm':'matchmaking','in_battle':'in_battle',
                    'in_party':'online','in_custom_batle_lobby':'online','watching_replay':'online',
                    'frontend':'online','in_party_frontend':'online','loading':'in_battle','battle':'in_battle',
                    'in_party_battle':'in_battle','in_party_matchmaking':'matchmaking','in_party_mm':'matchmaking'}
            if kind=='unavailable':self._native_presence='offline'
            elif status in states:self._native_presence=states[status]
            return False
        if kind not in ('subscribe','subscribed','unsubscribe','unsubscribed'):return False
        target=self.target(element.get('to'))
        if kind in ('subscribed','unsubscribed'):
            self.trace({'event':'native_social_subscription','kind':kind,'decision':'ack_ignored'})
            return True
        # Only stock's explicit Add/Remove UI produces subscribe/unsubscribe.
        # Refresh before deciding; Worker respond also enforces current incoming
        # ownership atomically, so a concurrent cancellation cannot approve a peer.
        cached_incoming=any(row['id']==target for row in self.snapshot()['incoming'])
        state=self.command('get')
        incoming=any(row['id']==target for row in state['incoming'])
        linked=any(row['id']==target for key in ('friends','outgoing') for row in state[key])
        if kind=='subscribe':
            if incoming:
                decision='accept';self.command('respond',{'target':target,'accept':True})
            elif cached_incoming:
                decision='stale_request_ignored'
            elif linked:
                decision='already_linked'
            else:
                decision='request';self.command('request',{'target':target})
        elif incoming:
            decision='decline';self.command('respond',{'target':target,'accept':False})
        elif linked:
            decision='remove';self.command('remove',{'target':target})
        else:
            decision='no_link'
        self.trace({'event':'native_social_subscription','kind':kind,'decision':decision})
        return True

    def start(self,publish,*,deliver_chat=None):
        if self._thread is not None:raise RuntimeError('social_already_started')
        self._publish=publish
        self._chat_delivery=deliver_chat
        self._thread=threading.Thread(target=self._run,name='native-social',daemon=True)
        try:self._thread.start()
        except Exception:
            self._thread=None;self._publish=None
            raise

    def _run(self):
        heartbeat=0
        while not self._stop.is_set():
            try:
                if time.monotonic()>=heartbeat:
                    self.command('heartbeat',{'state':self.presence_source()});heartbeat=time.monotonic()+15
                self.command('get')
            except Exception as error:
                self.trace({'event':'native_social_unavailable','error_type':type(error).__name__})
            try:
                self.poll_messages()
            except Exception:
                self.trace({'event': 'native_chat_unavailable'})
            self.poll_rooms()
            self._stop.wait(2)

    def stop(self):
        self._stop.set()
        if self._thread:
            if self._thread is not threading.current_thread():self._thread.join(timeout=6)
            if self._thread.is_alive():raise RuntimeError('native_social_stop_unconfirmed')
