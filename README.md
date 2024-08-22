 # SPS CBOX SSO

Add CUNY SSO integration to Commons In A Box

## Authorization and Authentication

When this plugin is activated, authorization via CUNY SSO is required for a user to register. The visitor's browser session is redirected to CUNY SSO for authentication. When authentication with CUNY SSO is successful, the information about that session is sent back to the Commons In A Box site, and the SSO
attributes are checked to determine if the user is authorized to register. If they are, the user can continue with registration.

Site admins can add users manually to the site and allow them to login with the standard WordPress form at `/login` or `/wp-login.php`.

Site admins can add a user's CUNY SSO EMPLID to the user's profile to connect an existing user account with CUNY SSO.

By default, authorization is SPS specific. The `sps_cbox_sso_can_register` filter can be used to override this behavior based on the available SAML attributes.

## Configuration

The plugin has a default configuration for CUNY SSO identiy provider (IdP) and service provider (SP) metadata.

The CUNY SSO IdP configuration was based on [the metadata file provided by CUNY IT](https://ssologin.cuny.edu/idp/metadata/oam-saml-metadata.xml).

Both configurations can be overridden or modified with the `sps_cbox_sso_saml_settings` filter.

### Certificates

A private key and certificate are required for the plugin to sign and verify SAML requests and responses. These can be stored as options in WordPress or filtered in code. No keys are provided by default with the plugin.

```
openssl req -new -x509 -key private.key -out certificate.crt -days 3650
wp option set sps_cbox_sso_x509_certificate $(cat certificate.crt)
wp option set sps_cbox_sso_private_key $(cat private.key)
```

Or, filter the keys with `sps_cbox_sso_private_key` and `sps_cbox_sso_x509_certificate`.

## Build and distribution

The plugin relies on a composer configuration for autoloading and the [underlying `onelogin/php-saml` library](https://github.com/SAML-Toolkits/php-saml). WP-CLI's [dist-archive command](https://github.com/wp-cli/dist-archive-command) can be used to build a versioned zip file for distribution.

```
composer install --no-progress --no-dev
composer dump-autoload
wp dist-archive ./
```
