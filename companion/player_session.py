"""Keep an owned native session alive using independently verified Epic proof.

The native process/bridge keep the same opaque session binding. Each extension
is authorized by the server with a current EOS Connect token for that same PUID.
The EOS SDK lives and ticks on the launch supervisor's thread, never the UI.
"""
from contextlib import contextmanager
import time

from .api_client import ApiClient, ApiError, NetworkError
from .config import load_session, save_session, SessionChangedError
from .eos.session import EosSession, EosLoginError
from .native_launch import session_snapshot


class PlayerSessionError(RuntimeError):
    pass


class SessionKeeper:
    def __init__(self, config, backend, *, api=None, clock=time.time):
        self.config = config
        self.backend = backend
        self.clock = clock
        self.current = load_session(config)
        session_snapshot(config, self.current or {}, now=int(clock()))
        self.api = api
        self.next_attempt = 0.0
        self.expiring = False
        backend.on_auth_expiring(self._expiring)

    def _expiring(self):
        # Never enter an EOS call recursively from the SDK's Tick callback.
        self.expiring = True

    def renew(self, token):
        now = int(self.clock())
        if (token.puid != self.current['puid'] or type(token.expires_at) is not int
                or token.expires_at <= now or self.current['expiresAt'] <= now):
            raise PlayerSessionError('login_required')
        if load_session(self.config) != self.current:
            raise PlayerSessionError('session_changed')
        # ApiClient's total deadline starts at construction. A game outlives
        # that 15-second budget, so each renewal needs its own bounded client.
        api = self.api if self.api is not None else ApiClient(
            self.config.api_base_url, self.config.client_version,
            self.current['token'], timeout=5.0, total_timeout=15.0)
        result = api.renew_session(token.token)
        expiry = result.get('expiresAt') if isinstance(result, dict) else None
        user = result.get('user') if isinstance(result, dict) else None
        # A replay cannot extend beyond its Epic proof; a shorter proof must
        # not roll back the previously verified expiration either.
        upper = max(self.current['expiresAt'], min(token.expires_at, now + 3605))
        if (type(expiry) is not int or not max(int(self.clock()), self.current['expiresAt']-1) < expiry <= upper
                or not isinstance(user, dict) or user.get('id') != self.current['puid']
                or set(result) != {'expiresAt', 'user'}):
            raise PlayerSessionError('invalid_session_renewal')
        updated = {**self.current, 'expiresAt': expiry}
        try:
            save_session(self.config, updated, expected_session=self.current)
        except SessionChangedError:
            raise PlayerSessionError('session_changed') from None
        self.current = updated
        self.expiring = False
        self.next_attempt = self.clock() + 15.0

    def poll(self):
        self.backend.tick()
        now = self.clock()
        if self.current['expiresAt'] <= now:
            raise PlayerSessionError('login_required')
        if (self.expiring or self.current['expiresAt'] - now <= 120) and now >= self.next_attempt:
            try:
                self.renew(self.backend.refresh_connect())
            except (ApiError, NetworkError, EosLoginError) as error:
                if isinstance(error, ApiError) and error.status in (401, 403):
                    raise PlayerSessionError('login_required') from None
                # A brief outage keeps the current still-valid session. Never
                # extend locally or retry in a tight loop after a server error.
                self.next_attempt = self.clock() + 15.0
                if self.current['expiresAt'] <= self.clock():
                    raise PlayerSessionError('login_required') from None


@contextmanager
def maintain_player_session(release):
    eos = release.eos
    with EosSession(release.config.repo_root/'runtime/EOSSDK-Win64-Shipping.dll',
                    eos['productId'], eos['sandboxId'], eos['deploymentId'],
                    eos['clientId'], eos['clientSecret'], call_timeout_s=30.0) as backend:
        keeper = SessionKeeper(release.config, backend)
        # Resume the explicitly selected existing account. No fallback portal,
        # new Connect account, or developer login is invoked during a game.
        keeper.renew(backend.login('persistent', allow_create_connect=False))
        yield keeper
