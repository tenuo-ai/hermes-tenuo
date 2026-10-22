# House-sitter

Let your house-sitter message your Hermes on the same bot you use, for the
length of their stay. Everything they send runs under their own warrant: the
guest room's light and comfort scene and a few sensors, nothing else, ending on
its own. Your messages run under yours.

What Hermes already does: everyone allowed on a bot gets the same tools (Hermes
issue #35479), pairings don't expire, and a Home Assistant entity allowlist
applies to the whole profile. The native way to give someone less is a second
profile with its own bot and allowlist. What the warrant adds: a different scope
per person on one bot, limits on services as well as entities (lights on and
off, never unlock), an end date, and revocation in one command.

Files: [`warrant.yaml`](warrant.yaml) for the sitter; [`owner.yaml`](owner.yaml)
for you, because enforcement covers every conversation.

## Set it up

You need both Telegram user IDs; the sitter's is the one you add to
`TELEGRAM_ALLOWED_USERS` (or their pairing). Do this before they send their first
message, so nothing they send runs unchecked.

```bash
tenuo-cli hermes setup                 # if you haven't
tenuo-cli warrant issue --template ~/.tenuo/recipes/hermes/house-sitter-owner.yaml --holder agent --out owner.warrant
tenuo-cli warrant issue --template ~/.tenuo/recipes/hermes/house-sitter.yaml --holder agent \
  --set stay=10d --set "controllable=[light.guest_room, scene.guest_room_comfort]" --out sitter.warrant
tenuo-cli hermes session attach --session telegram:<your user ID> --file owner.warrant
tenuo-cli hermes session attach --session telegram:<their user ID> --file sitter.warrant
tenuo-cli mode enforce
```

Attach any cron jobs you run, too (`cron_<job_id>`), or they'll be refused once
you enforce. Plans change: `tenuo-cli revocations add --id <warrant id>`, effective
on their next message.

## What it allows and refuses

| Their call | Result |
|------------|--------|
| `ha_list_entities` for lights, scenes or climate | allowed |
| `ha_get_state climate.guest_room` | allowed |
| `ha_call_service scene.turn_on scene.guest_room_comfort` | allowed |
| `ha_call_service light.turn_off light.guest_room` | allowed |
| `ha_call_service lock.unlock lock.front_door` | refused: Constraint 'domain' not satisfied |
| `ha_call_service light.turn_on light.bedroom` | refused: Constraint 'entity_id' not satisfied |
| `ha_call_service` with `data: {"area_id": …}` | refused: 'data' unknown field not allowed |
| `ha_get_state alarm_control_panel.home` | refused: Constraint 'entity_id' not satisfied |
| `ha_list_entities` with no domain (every entity, locks included) | refused: Constraint 'domain' not satisfied: missing required argument |
| anything after day 7 | refused: the warrant has expired |

`/new` or a reset gives them a new session; their warrant follows their user ID.

## Limits

- The warrant limits what Hermes can do, not what it can say. Hermes puts your
  memory and profile into the model's context, so the sitter can ask what it
  knows about you. Keep anything private out of memory, or give them a separate
  profile.
- In a group chat with both of you, each message runs under its sender's warrant.
  Attaching to the group's chat ID instead grants everyone in it.
- Domain, service and entity are checked independently, so pairs that don't
  exist in Home Assistant (`scene.turn_off`) are allowed and do nothing. The
  comfort scene runs whatever you put in it; keep it to the guest room.
