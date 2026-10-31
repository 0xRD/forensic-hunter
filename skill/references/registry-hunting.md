# Registry hunting

Analyst guide for hives in forhunt. Event ids and fields are in `forhunt.md`
(section "Registry"). Items marked **[K]** are analyst knowledge that was not
checked against a source in the session that wrote this file; treat them as
leads.

## Which source says what about a program

| Source | Says | Does not say |
|---|---|---|
| Prefetch | Ran, up to 8 times, from where, what it loaded | Who, arguments |
| BAM (23) | Ran, last time, under which SID | Earlier runs; entries age out after about a week **[K]** |
| UserAssist (22) | This user started it from the GUI, how often | Command-line runs |
| Amcache (21) | File was present, with SHA-1 and publisher | That it ran: the date is the key's, not a run **[K]** |
| ShimCache (20) | File was seen, order of appearance | That it ran; its date is the file's own modification time, so it can be years old or timestomped |

Never write "executed" from ShimCache or Amcache alone.

## Triage

```bash
forhunt search E -f ExePath~<name>                       # one program everywhere
forhunt search E -c Registry -e 11 -r 'ImagePath=\\(users|temp|programdata)\\'   # services in odd places
forhunt search E -c Registry -e 11 -r 'ImagePath=(cmd|powershell|mshta|rundll32)'
forhunt search E -c Registry -e 10                       # every autorun
forhunt search E -c Registry -e 23 -r 'ExePath=\\(users|temp)\\'
forhunt search E -c Registry -e 21 -f 'Publisher!~microsoft'
forhunt search E -c Registry -e 30                       # what users typed
forhunt search E -c Registry -e 42                       # local accounts and last logons
forhunt timeline E --since <t> --until <t>               # merged with logs, NTFS, prefetch
```

## Reading it

- A key's last write says when anything under it changed, not which value. On
  Run keys, every value shows the same date; only one of them changed then.
- Same for id 30: only the newest entry of a list was typed at that time.
- Network dates (`CreatedLocal`, `LastConnectedLocal`) are the machine's local
  time, unlike everything else. Read `TimeZone` (id 2) before comparing.
- A SAM account's creation is approximated by its `Names` key. `LogonCount`
  covers local logons only **[K]**.
- BAM paths use `\Device\HarddiskVolumeN`, prefetch `\VOLUME{...}`, ShimCache
  `C:\`, Amcache lower case: filter on the end of the path to cross them.
- `NoFileTime` or `NoRunTime`: the date is the key's, not a real event.

## Where it misleads

- A warning that a hive is dirty with no usable log means recent changes are
  missing, typically the last hours before collection.
- Only the current control set is read. Deleted keys and values are not
  recovered: an absent service proves nothing.
- ShimCache is written at shutdown **[K]**: on a system collected live, entries
  since the last boot are absent.
- Run key and service dates can be set by an attacker **[K]**. Check against
  `$J` and event logs (7045, 4697).
