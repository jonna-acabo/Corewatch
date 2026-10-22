# Live lab mode

CoreWatch runs on a mock network by default. Point it at real or virtual Junos devices and it polls them over
NETCONF (read-only) instead. Correlation, audits, the CLI view, metrics and the UI all work the same.

## 1. Start a two-router lab

You need a Linux host with KVM and [containerlab](https://containerlab.dev). vJunos-router is a free download
from Juniper's vJunos labs page; build it into a container image with vrnetlab, as described on the
containerlab `juniper_vjunosrouter` kind page.

```bash
cd lab
sudo containerlab deploy -t corewatch.clab.yml      # r1 172.20.20.2, r2 172.20.20.3
```

`r1` has an eBGP session to a "transit" on `ge-0/0/1` that has nothing connected, so CoreWatch shows a real
circuit-down incident straight away. The interface descriptions follow the `ROLE | far end | CID <id>`
convention that CoreWatch reads to build its circuit and carrier list.

## 2. Run CoreWatch against it

```bash
pip install -r backend/requirements-lab.txt
export LAB_DEVICES="r1=172.20.20.2,r2=172.20.20.3"
export LAB_USERNAME=admin
export LAB_PASSWORD='...'                 # or LAB_SSH_KEY=~/.ssh/id_ed25519
cd backend && python -m app.lab           # connectivity test: prints what it collected
uvicorn app.main:app                      # the dashboard now shows the lab
```

Things to try:

- `deactivate protocols bgp group IBGP` on r2, then commit: CoreWatch shows the BGP-down incident and the
  unapproved commit.
- `set interfaces ge-0/0/0 disable` on r1: the OSPF adjacency and link go down. CoreWatch remembers the neighbour
  from the previous poll and LLDP topology from earlier, so it can still say which link failed.

Use a lab account with read-only permissions. CoreWatch only runs `get-*` RPCs and never writes configuration.
