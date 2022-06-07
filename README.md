# nginx

An [Ansible][ansible] role for installing and managing [nginx][nginx] servers.

[ansible]: http://www.ansible.com/
[nginx]: http://nginx.org/
[galaxy]: http://galaxyproject.org/

## Requirements

This role installs nginx from APT on Debian systems, EPEL on Enterprise Linux
systems, or pkgin on SmartOS.  Other systems and installation methods are not
supported.

## Role Variables

All variables are optional.

### General Configuration

- `nginx_flavor` (default: `full`): nginx package to install (for choices, see the `nginx` metapackage providers for
  your Debian-based distribution). On RedHat-based distributions, this can either be `galaxy` (for "Galaxy nginx", which
  includes the nginx upload and pam modules), or any other value for EPEL nginx. This value is not used on pkgin/SmartOS
  installations. Generally TUS can be used and `full` is a safe default for the future.
- `nginx_servers`: A list of `server {}` (virtualhost) templates (relative to `templates/nginx/`, file ending `.j2` is
  automatically added to list entries when searching).
- `nginx_ssl_servers`: Like `nginx_servers`, but only installed if SSL is configured.
- `nginx_conf_http`: Set arbitrary options in the `http {}` section of `nginx.conf`. This is a hash (dictionary) where
  keys are nginx config options and values are the option's value.
- `nginx_default_redirect_uri`: When using nginx from EPEL, a default virtualhost is enabled. This option controls what
  URI the default virtualhost should be redirected to. nginx variables are supported.
- `nginx_enable_default_server` (default: `true`): Enable/disable the default EPEL virtualhost.
- `nginx_supervisor`: Run nginx under supervisor (requires setting certain supervisor variables).
- `nginx_conf_dir` (default: `/etc/nginx`): nginx configuration directory

### SSL Configuration

The `nginx_conf_ssl_certificate*` variables control the use of SSL. If unset, SSL will not be enabled. See Example
Playbook for usage.

- `nginx_conf_ssl_certificate`: File name of the SSL certificate on the remote host.
- `nginx_conf_ssl_certificate_key`: File name of the SSL private key on the remote host.
- `nginx_conf_ssl_ciphers`: The `ssl_ciphers` option in `nginx.conf`, this is a *list*.
- `nginx_conf_ssl_protocols`: The `ssl_protocols` option in `nginx.conf`, this is a *list*.

### External SSL Configuration

- `nginx_ssl_role` (default: undefined): Role to run to set up SSL. This allows the use of (for example)
  [usegalaxy_eu.certbot][usegalaxy_eu-certbot], which typically must run after nginx is set up and running on port 80,
  but before nginx attempts to use SSL (since until certbot runs, the certs that nginx expects do not exist yet).
  Setting this will cause the SSL role to be run at the appropriate point in this role. See also `nginx_ssl_servers`.
- `nginx_conf_ssl_certificate`: File name of the SSL certificate.
- `nginx_conf_ssl_certificate_key`: File name of the SSL private key.

In this mode, the `nginx_conf_ssl_certificate*` variables should be absolute paths.

[usegalaxy_eu-certbot]: https://github.com/usegalaxy_eu/ansible-certbot/

### Playbook SSL Configuration

If `nginx_ssl_role` is unset, you can use this role to copy your certificate and key from the playbook.

- `nginx_ssl_conf_dir` (default: `<nginx_conf_dir>/ssl`): Where to copy SSL certificates and other SSL-related files to.
- `nginx_ssl_src_dir` (default: `files/ssl`): Where to copy SSL certificates from.
- `sslkeys`: A hash (dictionary) containing private keys. Keys are the filenames (without leading path elements) matching
  `nginx_conf_ssl_certificate_key`.
- `nginx_conf_ssl_trusted_certificate`: File name of trusted certificates for OCSP stapling (setting enables stapling).

In this mode, the `nginx_conf_ssl_certificate*` variables should be relative paths. However, for legacy reasons, they
can be absolute paths to the files on the remote host. If this is the case, the certs are searched for in
`nginx_ssl_src_dir` with the directory portion of the path stripped. If the path is not absolute, it is relative to
`nginx_ssl_src_dir` for the source, and relative to `nginx_ssl_conf_dir` for the destination.

### SELinux

If SELinux is in enforcing mode, several additional actions will be taken:

- If `certbot_well_known_root` is set, it will be updated to allow the type `httpd_sys_content_t` permissions on all subdirectories
- `nginx_selinux_allow_local_connections` (default: `false`): Allow nginx to connect to localhost

## Dependencies

Although not a requirement, [geerlingguy.repo-epel][repo-epel] can be used to enable EPEL with Ansible.

[repo-epel]: https://galaxy.ansible.com/geerlingguy/repo-epel/

## Example Playbook

Here are a few playbook examples depending on where you're getting your certificates

### Local SSL Certificates

Install nginx with SSL certs stored in the playbook (cert at `{{ playbook_dir }}/files/ssl/snakeoil_cert.pem`):

```yaml
- name: Install and configure nginx
  hosts: webservers
  vars:
    sslkeys:
      snakeoil_privatekey.pem: |
        -----BEGIN PRIVATE KEY-----
        MIIE...
        -----END PRIVATE KEY-----
    nginx_conf_ssl_certificate: snakeoil_cert.pem
    nginx_conf_ssl_certificate_key: snakeoil_privatekey.pem
    nginx_servers:
      - vhost1
      - vhost2
    nginx_conf_http:
      client_max_body_size: 1g
  roles:
    - galaxyproject.nginx
```

### Let's Encrypt

Install nginx with SSL certs obtained from Let's Encrypt with Certbot using [usegalaxy_eu.certbot][usegalaxy_eu-certbot]:

```yaml
- name: Install and configure nginx
  hosts: webservers
  vars:
    nginx_conf_ssl_certificate: /etc/ssl/certs/fullchain.pem
    nginx_conf_ssl_certificate_key: /etc/ssl/private/private.pem
    nginx_servers:
      - vhost1
      - vhost2
    nginx_ssl_servers:
      - vhost1_ssl
      - vhost2_ssl
    nginx_conf_http:
      client_max_body_size: 1g
    nginx_ssl_role: usegalaxy_eu.certbot
    certbot_auth_method: --webroot
    certbot_domains:
      - vhost1.example.org
      - vhost2.example.org
    certbot_admin_email: webmaster@example.org
    certbot_agree_tos: --agree-tos
    certbot_well_known_root: /var/www/_well-known_root
    certbot_post_renewal: |
      systemctl restart nginx || true
  roles:
    - galaxyproject.nginx
```

In `templates/nginx/vhost1.j2` and `templates/nginx/vhost2.j2`, be sure to add something like:

```nginx
server {
    location /.well-known/ {
        root {{ certbot_well_known_root }};
    }
}
```

### Self-Signed Certs

Install nginx and use a generated and self-signed SSL certificate (good option for testing secured services behind a firewall)

```yaml
- name: Install and configure nginx
  hosts: webservers
  vars:
    nginx_servers:
      - vhost1
      - vhost2
    nginx_ssl_servers:
      - vhost1_ssl
      - vhost2_ssl
    nginx_conf_http:
      client_max_body_size: 1g
    nginx_ssl_role: galaxyproject.self_signed_certs
    openssl_domains: # Identical behaviour to certbot_domains
      - vhost1.example.org
      - vhost2.example.org
    # These can be set to wherever you want your certificates and PK stored.
    nginx_conf_ssl_certificate_key: /etc/ssl/private/{{ openssl_domains[0] }}.pem
    nginx_conf_ssl_certificate: /etc/ssl/certs/{{ openssl_domains[0] }}.crt
  roles:
    - galaxyproject.nginx
```

License
-------

[Academic Free License ("AFL") v. 3.0][afl]

[afl]: http://opensource.org/licenses/AFL-3.0

Author Information
------------------

- [Nate Coraor](https://github.com/natefoo)
- [Helena Rasche](https://github.com/hexylena)
