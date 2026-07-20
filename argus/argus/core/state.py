from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .events import ArgusEvent, make_state_change_event


class ArgusMode(str, Enum):
    DISARMED = "DISARMED"
    ARMED_HOME = "ARMED_HOME"
    ARMED_AWAY = "ARMED_AWAY"
    LOCKDOWN = "LOCKDOWN"


@dataclass(slots=True)
class TransitionResult:
    event: ArgusEvent
    actions: list[str]


class ArgusStateMachine:
    def __init__(self, host: str, initial: ArgusMode = ArgusMode.DISARMED) -> None:
        self.host = host
        self.state = initial

    def transition(self, trigger: str, reason: str) -> TransitionResult | None:
        old = self.state
        new = self._next_state(trigger)
        if new == old:
            return None
        self.state = new

        actions: list[str] = []
        if new == ArgusMode.LOCKDOWN:
            actions = ["workstation_locked", "sms_sent", "evidence_capture_queued", "network_isolated"]

        event = make_state_change_event(
            host=self.host,
            old_state=old.value,
            new_state=new.value,
            reason=reason,
        )
        event.actions_taken = actions
        return TransitionResult(event=event, actions=actions)

    def _next_state(self, trigger: str) -> ArgusMode:
        if trigger == "arm":
            if self.state == ArgusMode.DISARMED:
                return ArgusMode.ARMED_HOME
            return self.state

        if trigger == "disarm":
            return ArgusMode.DISARMED

        if trigger == "away_timeout":
            if self.state == ArgusMode.ARMED_HOME:
                return ArgusMode.ARMED_AWAY
            return self.state

        if trigger == "owner_return":
            if self.state == ArgusMode.ARMED_AWAY:
                return ArgusMode.ARMED_HOME
            return self.state

        if trigger == "threat_detected":
            if self.state in {ArgusMode.ARMED_HOME, ArgusMode.ARMED_AWAY}:
                return ArgusMode.LOCKDOWN
            return self.state

        return self.state
