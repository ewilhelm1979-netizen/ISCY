# TLS and Reverse Proxy

ISCY kann hinter einem Reverse Proxy betrieben werden. Der Proxy terminiert HTTPS, entfernt unsichere Client-Header und leitet nur bewusst gesetzte Betriebsinformationen weiter.

## Vertrauensgrenze

- Production mit `RUST_BACKEND_BIND=0.0.0.0:*` verlangt `ISCY_TRUSTED_PROXY_CONFIGURED=1`.
- `ISCY_TRUST_PROXY_IDENTITY_HEADERS=1` darf nur gesetzt werden, wenn der Proxy eingehende `x-iscy-*` Identity-Header entfernt.
- Ohne dieses Vertrauen blockiert ISCY solche Header in Production.
- HSTS wird nur gesetzt, wenn `ISCY_HSTS_ENABLED=1` und `ISCY_HTTPS_CONFIRMED=1` aktiv sind.

## Proxy-Anforderungen

- HTTPS fuer Nutzerzugriff terminieren.
- HTTP nach HTTPS weiterleiten.
- Eingehende Identity-Header entfernen:
  - `x-iscy-tenant-id`
  - `x-iscy-user-id`
  - `x-iscy-user-email`
  - `x-iscy-roles`
  - `x-iscy-is-staff`
  - `x-iscy-is-superuser`
- Falls Header-Kontext gebraucht wird, diese Header nur aus einer vertrauenswuerdigen lokalen Auth- oder SSO-Quelle neu setzen.
- `X-Forwarded-Proto` und Client-IP nur aus vertrauenswuerdigen Netzen uebernehmen.
- Upload-Limits mit ISCY-Parserlimits abstimmen.

## HSTS

HSTS ist ein Production-Schalter, kein Development-Default. Vor Aktivierung pruefen:

- alle Nutzerzugriffe laufen ueber HTTPS,
- Zertifikatsrotation ist geklaert,
- Subdomains sind einbezogen oder bewusst ausgeschlossen,
- Rollback ist fachlich akzeptiert.

ISCY setzt dann:

```text
Strict-Transport-Security: max-age=15552000; includeSubDomains
```

## Beispiel

```nginx
proxy_set_header x-iscy-tenant-id "";
proxy_set_header x-iscy-user-id "";
proxy_set_header x-iscy-user-email "";
proxy_set_header x-iscy-roles "";
proxy_set_header x-iscy-is-staff "";
proxy_set_header x-iscy-is-superuser "";
proxy_set_header X-Forwarded-Proto https;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```

Das Beispiel ist eine Arbeitsgrundlage. Die konkrete Proxy-Konfiguration muss zur Zielumgebung passen.
