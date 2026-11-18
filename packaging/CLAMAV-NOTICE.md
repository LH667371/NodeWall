# ClamAV and bundled components

The NodeWall offline bundle contains ClamAV and its runtime dependencies from
the signed Alpine Linux v3.24 repositories. `PACKAGES.txt` inside each engine
archive records the exact package versions. ClamAV is licensed under GPL-2.0;
its corresponding upstream source, license and Alpine packaging recipe and
patches are included in `source/`. Upstream sources are also available at
https://github.com/Cisco-Talos/clamav and the Alpine packaging recipes at
https://gitlab.alpinelinux.org/alpine/aports. Alpine
package sources are also published at https://dl-cdn.alpinelinux.org/alpine/.
The other bundled packages retain their respective licenses.

The `main`, `daily`, and `bytecode` CVD files are ClamAV signature databases.
ClamAV verifies their upstream digital signatures before the offline bundle
is created. Consult https://www.clamav.net/ for database terms and updates.
