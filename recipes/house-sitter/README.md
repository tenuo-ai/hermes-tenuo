# House-sitter

Let your house-sitter message your Hermes for the length of their stay. Their
conversation gets its own warrant: the guest room's light and comfort scene, a
few sensors, nothing else, and it ends on its own. Your own conversation keeps
whatever you give it; the sitter's warrant never reaches it.

Today, everyone who can talk to your Hermes gets the same tools, and Home
Assistant's own limits are set and undone by hand.

[`warrant.yaml`](warrant.yaml): `ha_get_state` on three entities, and
`ha_call_service` for `light`/`scene` `turn_on`/`turn_off` on two, for 7 days.
Set the temperature you want in a Home Assistant scene; the warrant refuses
service `data`, so the sitter can't target an area or "all".

## Set it up

```bash
hermes-tenuo setup                     # if you haven't
cp recipes/house-sitter/warrant.yaml sitter.yaml   # your entity IDs and the stay
tenuo-cli warrant issue --template sitter.yaml --holder agent --out sitter.warrant
# the sitter sends their first message; their session ID is in:
tenuo-cli calls list --limit 5         # observe mode, or the first refusal names it
hermes-tenuo session attach --session <their session ID> --file sitter.warrant
tenuo-cli mode enforce
```

Plans change: `tenuo-cli revocations add --id <warrant id>`. No restart.

## What it allows and refuses

| Call | Result |
|------|--------|
| `ha_get_state climate.guest_room` | allowed |
| `ha_call_service scene.turn_on scene.guest_room_comfort` | allowed |
| `ha_call_service light.turn_off light.guest_room` | allowed |
| `ha_call_service lock.unlock lock.front_door` | refused: Constraint 'domain' not satisfied |
| `ha_call_service light.turn_on light.bedroom` | refused: Constraint 'entity_id' not satisfied |
| `ha_call_service` with `data: {"area_id": …}` | refused: 'data' unknown field not allowed |
| `ha_get_state alarm_control_panel.home` | refused: Constraint 'entity_id' not satisfied |
| anything from a conversation with nothing attached | refused, with the attach command |
| any call after day 7 | refused: the warrant has expired |
