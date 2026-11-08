# Production edge (tls13_stable)

Do **not** set `SWIF_LAB=1` or `SWIF_ALLOW_NULL=1` on public nodes.

```powershell
.\swif-edge.exe `
  --listen 0.0.0.0:443 `
  --mask tls13_stable `
  --key C:\swif\server.key `
  --pub-out C:\swif\server.pub `
  --sni cdn.example.com `
  --tls-cert C:\swif\cover.crt `
  --tls-key C:\swif\cover.key `
  --cover 127.0.0.1:8443
```

- `--cover` must point at a live HTTP(S) origin the cert/SNI match.
- Client share: `swif://YOUR_IP:443?pub=<server.pub hex>&mask=tls13_stable&sni=cdn.example.com&tls_verify=webpki`
- Optional lab-only: `quic_stable` behind `SWIF_ALLOW_QUIC_STABLE=1` (not default prod).
