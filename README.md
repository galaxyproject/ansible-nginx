# nginx

An [Ansible][ansible] role for installing and managing [nginx][nginx] servers.

[ansible]: http://www.ansible.com/
[nginx]: http://nginx.org/
[galaxy]: http://galaxyproject.org/

## Requirements

This role installs nginx from APT on Debian-based systems, the AppStream DNF repository on Enterprise Linux systems, or
pkgin on SmartOS. Other systems and installation methods are not supported.

## Role Variables

All variables are optional.

### General Configuration

| name | default | description |
| --- | --- |
| `nginx_flavor` | `core` | nginx package to install (for choices, see the `nginx` metapackage providers for your Debian-based distribution, the value is the package name after `nginx-`). Ignored on RedHat- and pkgin-based distributions. |
| `nginx_servers` | empty list | A list of `server {}` (virtualhost) templates (relative to `nginx_server_src_dir`, file ending `.j2` is automatically added to list entries when searching). |
| `nginx_ssl_servers` | empty list | Like `nginx_servers`, but only installed if SSL is configured. |
| `nginx_conf_http` | undefined | Set arbitrary options in the `http {}` section of `nginx.conf`. This is a hash (dictionary) where keys are nginx config options and values are the option's value. |
| `nginx_default_redirect_uri` | undefined | When using nginx from AppStream, a default `server {}` is enabled. This option controls what URI the default server should be redirected to. nginx variables are supported. |
| `nginx_enable_default_server` | `true` | Enable/disable the default AppStream `server {}`. |
| `nginx_conf_dir` | `/etc/nginx` | nginx configuration directory |
| `nginx_user` | undefined (use distribution default) | User to run nginx as |
| `nginx_group` | undefined (use distribution default) | Group to run nginx as |

### SSL Configuration

The `nginx_conf_ssl_certificate` and `nginx_conf_ssl_certificate_key` variables control the use of SSL. If unset, SSL
will not be enabled.

The role attempts to implement SSL options specified by the best-practice [Mozilla SSL Configuration
Generator][mozconfig] tool, with the following caveats:

- The configuration is not pulled live from the configurator, and is based on nginx 1.14.1 and OpenSSL 1.1.1
- Only `http {}` section options are set by the role, options for the `server {}` section (such as the HSTS header) need
  to be set in your server templates (`nginx_ssl_servers`)
- The "old" generator profile is not supported due to being insecure (if you want it, it can be configured manually)
- `ssl_protocols` is set even if you choose to disable the configurator profile since TLS < 1.2 are insecure but remain
  enabled by default in the compiled-in nginx defaults. If you truly desire the compiled-in default, set
  `nginx_conf_ssl_protocols` to `null`, or set an explicit list.
- `ssl_session_timeout` is decreased based on [this discussion](https://github.com/mozilla/server-side-tls/issues/198)

[mozconfig]: https://ssl-config.mozilla.org/

### Common SSL Configuration options

| name | default | description |
| `nginx_ssl_config_profile` | `default` | Which Mozilla SSL Configuration Generator profile to use (`modern`, `intermediate`), or `default` to disable profile defaults. |
| `nginx_ssl_conf_dir` | `{{ nginx_conf_dir }}/ssl` | Remote directory where SSL certificates, keys, and other SSL-related files will be copied to. |
| `nginx_conf_ssl_certificate` | undefined | File name of the SSL certificate. |
| `nginx_conf_ssl_certificate_key` | undefined | File name of the SSL private key. |
| `nginx_conf_ssl_trusted_certificate`| undefined | File name of trusted certificates for OCSP stapling. |
| `nginx_conf_ssl_protocols` | determined by profile | The `ssl_protocols` option in `nginx.conf`, this is a *list*. |
| `nginx_conf_ssl_ciphers` | determined by profile | The `ssl_ciphers` option in `nginx.conf`, this is a *list*. |

### External SSL Configuration

In this mode, this role passes execution to an external role at the appropriate point (in between configuring non-SSL
and SSL options and servers) so that SSL certificates can be installed. This allows the use of (for example)
[usegalaxy_eu.certbot][usegalaxy_eu-certbot] to obtain certificates from [Let's Encrypt][lets-encrypt], which typically
must run after nginx is set up and running on port 80, but before nginx attempts to use SSL (since until Certbot runs,
the certs that nginx expects do not exist yet).

The `nginx_conf_ssl_certificate` and `nginx_conf_ssl_certificate_key` variables should be set to absolute paths when
using this mode.

| name | default | description |
| `nginx_ssl_role` | undefined | Role to run to set up SSL. See also `nginx_ssl_servers`. |

[usegalaxy_eu-certbot]: https://github.com/usegalaxy-eu/ansible-certbot/
[lets-encrypt]: https://letsencrypt.org/

### Playbook SSL Configuration

If `nginx_ssl_role` is unset, you can use this role to copy your certificate and key from the playbook.

Prior versions of this role expected SSL key contents to be found in a dictionary named `sslkeys`. Beginning with 
version 1.0.0, keys should be (vaulted) files in the playbook. **This is a breaking change in version 1.0.0.**

| name | default | description |
| `nginx_ssl_src_dir` | `files/ssl` | Playbook directory that will be searched for certificate and key files. |

If the `nginx_conf_ssl_certificate` and `nginx_conf_ssl_certificate_key` variables are absolute paths, it is assumed
that they are managed by something other than this role and are expected to already exist on the remote host. Otherwise,
they will be copied from the playbook to `nginx_ssl_conf_dir`.

### SELinux

If SELinux is in enforcing mode, several additional actions will be taken:

- If `certbot_well_known_root` is set, it will be updated to allow the type `httpd_sys_content_t` permissions on all subdirectories
- If `nginx_selinux_allow_local_connections` is enabled (default: `false`), allow nginx to connect to localhost

## Dependencies

- [community.general](https://galaxy.ansible.com/ui/repo/published/community/general/), if `pkgin` is the package
  manager or SELinux is enabled and `cerbot_well_known_root` is defined.

## Example Playbook

Here are a few playbook examples depending on where you're getting your certificates

### Local SSL Certificates

Install nginx with SSL certs copied from the playbook at `{{ playbook_dir }}/files/ssl/snakeoil_{cert,privatekey}.pem`):


```yaml
- name: Install and configure nginx
  hosts: webservers
  vars:
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
