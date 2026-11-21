# Install with Docker

One command starts everything: the API, the live syslog listener and the web interface. Nothing else needs installing, no Python and no Node.js. With no settings changed and no API key it starts in demo mode, with the built-in scenarios ready to load.

To run netlog without Docker, for development, see the README instead.

## Requirements

- **Windows 10 or 11, or macOS:** [Docker Desktop](https://docs.docker.com/desktop/). On Windows it runs on WSL2, which its installer sets up.
- **Linux:** Docker Engine with the Compose plugin.
- Docker Compose **2.24 or newer**. Check with `docker compose version`.
- Git, to download the project.
- About 2 GB of free disk space while building. The finished images are much smaller than that; the build tools stay in the build stages.

The commands below work as written in PowerShell, and in a Linux or macOS terminal. Docker Desktop must be running before you start.

## Start it

```powershell
git clone https://github.com/siddxwar04/Network-Log.git
cd Network-Log/deploy
docker compose up -d --build
```

The first start builds the two images and takes a few minutes. Later starts take seconds. `up -d` returns while the app is still starting; to see when it is ready:

```powershell
docker compose ps
```

Both lines should say `(healthy)` in the STATUS column, within about 30 seconds of the build finishing.

## Open it

Go to **http://localhost:8080** in a browser on the same computer.

Pick a demo scenario on the first page, for example *02_cascade*, and watch it being analyzed. In demo mode the demo scenarios show explanations stored with them, and any file you upload gets the built-in explanation, written from templates. Nothing leaves your computer.

### There is no login

Anyone who can open the web address can read every log you load into it, change the detection rules and delete uploads. That is why it is published on **127.0.0.1** only, which this computer alone can reach. Before you change `NETLOG_WEB_BIND` to make it reachable from other machines, make sure everyone on that network may see your logs. There is no HTTPS either: on an untrusted network, put it behind a reverse proxy that adds both, or reach it through an SSH tunnel.

## Settings

Every setting goes in one file, `deploy/.env`. Make it from the example, which explains each line:

```powershell
cp .env.example .env
```

(run this in the `deploy` folder). Every value in the example is the default, so you only change the lines you need. `.env` is ignored by git, so your key and webhook addresses never end up in a commit. After changing it, apply the change with:

```powershell
docker compose up -d
```

Any setting in `backend/netlog/config/defaults.toml` can be put in `.env` too, as `NETLOG__` then the section, two underscores and the setting's name in capitals. For example `gap_seconds` under `[correlation]`:

```
NETLOG__CORRELATION__GAP_SECONDS=90
```

A name that is not a setting, or a value of the wrong kind (text where a number belongs), stops the app at start with a message saying which line is wrong. Read it with `docker compose logs backend`.

## Add an LLM key

Without a key, netlog uses its built-in explanations. To have an LLM write them, set these three lines in `deploy/.env`:

```
NETLOG_LLM_PROVIDER=openai
NETLOG_LLM_MODEL=
NETLOG_LLM_API_KEY=your-key-here
```

Leave the model empty for the default. Then `docker compose up -d`. The banner saying "demo mode" disappears from the web interface, and the Regenerate button on an incident page becomes available.

The LLM only ever sees a short evidence pack about one incident, never your log files, and names, addresses and usernames in it are replaced with stand-ins before it leaves your computer (`NETLOG__REDACTION__ENABLED`). Each explanation costs one or two requests.

## Send logs from your devices

The live listener is on by default and listens on port 5514, UDP and TCP, but only on 127.0.0.1, so at first only this computer can send to it. To receive from devices on your network:

1. Find this computer's address on the network the devices can reach, for example `192.168.1.20` (`ipconfig` on Windows, `ip addr` on Linux).
2. In `deploy/.env`, publish the listener on that address. Use the address itself, not `0.0.0.0`: syslog has no authentication, and anyone who can reach the port can send messages that look like they come from your routers.

   ```
   NETLOG_SYSLOG_BIND=192.168.1.20
   ```

3. `docker compose up -d`.
4. On Windows, allow the port through the firewall when Windows asks, or add a rule for UDP and TCP 5514.
5. On each Cisco IOS device, in configuration mode:

   ```
   logging host 192.168.1.20 transport udp port 5514
   logging trap informational
   logging origin-id hostname
   service timestamps log datetime msec
   ```

   `logging trap informational` sends everything from severity 6 (informational) up, which includes interface, OSPF, BGP and configuration messages. `logging origin-id hostname` makes the device put its own name in each message. `service timestamps` makes it put its own date and time on each message.

6. Open **Live** in the web interface. The device appears under Senders within seconds of its next message.

With `logging origin-id hostname`, each device is named by the name in its messages. Without it, a Cisco device does not put its own name in the messages it sends this way, and netlog names it by the address it sends from. On a **Linux** host that is the device's real address. **Docker Desktop on Windows and macOS** can pass every message on from one internal address instead (such as 192.168.65.1), and then devices without `logging origin-id hostname` all look like a single device and their incidents run together. Check the Senders list after connecting a second device. If they share one address, add `logging origin-id hostname` to every device, or run the Docker install on a Linux machine or a Linux virtual machine; uploading log files is not affected.

For a Linux server, add a line to rsyslog (for example in `/etc/rsyslog.d/90-netlog.conf`) and restart rsyslog:

```
*.* @192.168.1.20:5514
```

(`@` sends over UDP, `@@` over TCP.)

To try the listener without a device, a sample log can be replayed into it from a development install: see "Live syslog" in [docs/CLI.md](CLI.md).

### Only accepting your own devices

`NETLOG__LIVE__ALLOWED_SENDERS=["192.168.1.1", "192.168.1.2"]` drops messages from any other address. On a **Linux** host this works as expected. On **Docker Desktop**, for the reason above, the list would refuse your devices if they all arrive from one internal address: check the Senders list on the Live page first, and if every device shows the same address, leave the list empty and rely on the address the port is published on, and on your firewall, instead.

### Port 514

Devices that cannot change the port send to 514. Publish the listener there with `NETLOG_SYSLOG_PORT=514`. Docker publishes it for you, but on Linux another syslog daemon may already be using 514; stop it or forward from it.

## Back up and restore

Everything netlog keeps (the database, uploaded files and your rule file) is in one Docker volume, `netlog_data`. It survives restarts, rebuilds and upgrades; only `docker compose down -v` deletes it.

To back it up into a file `netlog-backup.tar.gz` in the current folder, stop the API first so the database is copied in a consistent state:

```powershell
docker compose stop backend
docker run --rm -v netlog_data:/data -v "${PWD}:/backup" alpine tar czf /backup/netlog-backup.tar.gz -C /data .
docker compose start backend
```

To restore it, replacing everything currently in the volume:

```powershell
docker compose down
docker run --rm -v netlog_data:/data -v "${PWD}:/backup" alpine sh -c "rm -rf /data/* && tar xzf /backup/netlog-backup.tar.gz -C /data"
docker compose up -d
```

Run these in the `deploy` folder. `${PWD}` means the current folder in both PowerShell and bash.

## Upgrade

```powershell
git pull
docker compose up -d --build
```

Your data stays in the volume. When a new version changes the database, it updates it at start, by itself; back up first if you want to be able to go back.

## Stop and start

```powershell
docker compose stop      # stop, keep everything
docker compose start     # start again
docker compose logs -f   # follow what it prints; Ctrl+C to stop following
```

The containers start again by themselves after a reboot, as long as Docker starts.

## Remove it completely

In the `deploy` folder:

```powershell
docker compose down -v --rmi all
```

This removes the containers, the `netlog_data` volume with every upload, incident and rule, and the two images. Back up first if you might want the data. Then delete the `Network-Log` folder. Docker keeps its build cache until you clear it with `docker builder prune`.

## Check an install

A scripted smoke test builds and starts a second, separate copy of the stack (project `netlog-smoke`, on ports 18080 and 15514), waits until it is healthy, checks the web pages, loads the cascade demo through the API and checks that an incident comes back, sends one syslog message over UDP and one over TCP and checks that both arrive, then removes that copy and its volume. It never reads your `.env` and never touches your own install or its data. It needs Python 3.11 or newer, and nothing else installed. From the repository folder:

```powershell
python deploy/smoke_test.py
```

It prints one `ok` line per check and ends with `PASSED`, or `FAILED` with the reason and the containers' last log lines. `--keep` leaves the smoke stack running to look at.

## What is inside

| File | What it is |
|---|---|
| `deploy/compose.yaml` | The two services, the ports and the data volume |
| `deploy/.env.example` | Every setting for the Docker install, with its default and what it does |
| `deploy/backend.Dockerfile` | The API with the live listener: Python, the netlog package, the demo scenarios |
| `deploy/frontend.Dockerfile` | The web interface: the built pages, served by nginx |
| `deploy/nginx.conf` | Serves the pages and passes `/api` on to the API |
| `deploy/smoke_test.py` | The smoke test |

Two containers run. **backend** runs the API and the live listener as an ordinary user (uid 10001), with a read-only file system apart from the data volume and a scratch folder; only its syslog port is published. **frontend** runs nginx as an ordinary user, serves the web interface and passes every `/api` request on to the backend, so the browser talks to one address and the API itself is never published. Neither container has any Linux capabilities or can gain privileges.
