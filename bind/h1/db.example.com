;
; BIND data file for local loopback interface
;
$TTL   604800
@   IN  SOA localhost. root.localhost. (
                  2     ; Serial
             604800     ; Refresh
              86400     ; Retry
            2419200     ; Expire
             604800 )   ; Negative Cache TTL
;


@   IN  NS  ns.dnslabattacker.net.


www IN  A   1.1.1.1
