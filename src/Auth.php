<?php
/**
 * Manage authorization with CUNY SSO.
 *
 * @package sps-cbox-sso
 */

namespace SPS\CBOX\SSO;

use SPS\CBOX\SSO\Config;
use OneLogin\Saml2\Auth as SAML2_Auth;
use WP_User;

/**
 * Manage authorization with CUNY SSO.
 */
class Auth {
	/**
	 * The Saml2 Auth object.
	 *
	 * @var SAML2_Auth|false
	 */
	private $saml = false;

	/**
	 * The prefixed used to identify temporary signups.
	 *
	 * @var string
	 */
	private $signup_prefix = 'spssso';

	/**
	 * The name of the cookie used to store SSO authorization.
	 *
	 * @var string
	 */
	private $cookie_name = 'sps_cbox_sso_authorization';

	/**
	 * Provide access to the Saml2 Auth object.
	 *
	 * @return SAML2_Auth
	 */
	public function saml() {
		if ( $this->saml ) {
			return $this->saml;
		}

		$config = Config::saml_settings();

		try {
			$this->saml = new SAML2_Auth( $config );
		} catch ( \Exception $e ) {
			die( wp_kses_post( $e->getMessage() ) );
		}

		return $this->saml;
	}

	/**
	 * Get the signup prefix.
	 *
	 * @return string
	 */
	public function get_signup_prefix(): string {
		return $this->signup_prefix;
	}

	/**
	 * Get cookie data from the SSO authorization cookie.
	 *
	 * @return array
	 */
	public function get_cookie_data(): array {
		$cookie = $_COOKIE[ $this->cookie_name ] ?? '';

		if ( ! $cookie ) {
			return array();
		}

		return explode( '|', $cookie );
	}

	/**
	 * Check if the visiting user is authorized to register
	 * via CUNY SSO.
	 *
	 * @return bool
	 */
	public function is_sso_authorized(): bool {
		$cookie_data = $this->get_cookie_data();

		if ( 4 !== count( $cookie_data ) ) {
			return false;
		}

		list( $username, $expiration, $token, $hash ) = $cookie_data;

		if ( ! $username ) {
			return false;
		}

		$user = $this->get_user( $username );

		if ( $user ) {
			$fragment = substr( $user->user_pass, 8, 4 );
		} else {
			$signup   = $this->get_temp_signup( $username );
			$fragment = $signup ? $signup->activation_key : '';
		}

		if ( ! $fragment ) {
			$this->clear_sso_authorization_cookie();
			return false;
		}

		$key = wp_hash( $username . '|' . $fragment . '|' . $expiration . '|' . $token, 'auth' );

		$hash_expected = hash_hmac( 'sha256', $username . '|' . $expiration . '|' . $token, $key );

		if ( ! hash_equals( $hash, $hash_expected ) ) {
			$this->clear_sso_authorization_cookie();
			return false;
		}

		return true;
	}

	/**
	 * Handle an error condition.
	 *
	 * @param string $error    The error message.
	 * @param int    $response The HTTP response code.
	 */
	public function handle_error( string $error, int $response = 500 ): void {

		$message = sprintf(
			'<p>%s</p><p><a href="%s">%s</a></p>',
			esc_html( $error ),
			esc_url( Config::logout_url() ),
			esc_html__( 'Log out of CUNY SSO connection.', 'sps-cbox-sso' )
		);

		wp_die(
			$message, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			esc_html__( 'Error authorizing with CUNY SSO', 'sps-cbox-sso' ),
			array(
				'response' => $response, // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			)
		);
	}

	/**
	 * Determine whether the user is authorized to register.
	 *
	 * @return bool Whether the user is authorized to register.
	 */
	private function can_register(): bool {
		$attributes = $this->saml()->getAttributes();

		/**
		 * Filter whether a user is authorized to register via CUNY SSO.
		 *
		 * @param bool   $can_register Whether the user is authorized to register.
		 * @param array  $attributes   The SAML attributes for the user.
		 */
		return apply_filters( 'sps_cbox_sso_can_register', false, $attributes );
	}

	/**
	 * Process a SSO response from the IdP.
	 */
	public function verify_sso_response(): void {
		try {
			$this->saml()->processResponse();
		} catch ( \Throwable $e ) {
			$this->handle_error( $e->getMessage() );
		} catch ( \Exception $e ) {
			$this->handle_error( $e->getMessage() );
		}

		if ( ! empty( $this->saml()->getErrors() ) ) {
			$this->handle_error( 'SAML response errors: ' . implode( ', ', $this->saml()->getErrors() ) );
		}

		if ( ! $this->saml()->isAuthenticated() ) {
			$this->handle_error( 'User is not authenticated.', 403 );
		}

		// CUNY IT passes EMPLID as the NameID. We use this as the key
		// to associate with local WordPress accounts.
		$emplid = $this->saml()->getNameId();

		if ( defined( 'SPS_CBOX_SSO_DEBUG' ) && SPS_CBOX_SSO_DEBUG ) {
			$attributes = $this->saml()->getAttributes();

			$debug_id = wp_insert_post(
				array(
					'post_title'  => sanitize_text_field( $emplid ) . ' SSO Authorization attempt ' . gmdate( 'Y-m-d H:i:s' ),
					'post_status' => 'publish',
					'post_type'   => 'sps-cbox-sso-debug',
				)
			);

			if ( ! is_wp_error( $debug_id ) ) {
				update_post_meta( $debug_id, 'sps_cbox_sso_attributes', $attributes );
			}
		}

		if ( false === $this->can_register() ) {
			$this->handle_error( 'User is not authorized to register.', 403 );
		}

		$user = $this->get_user( $emplid );

		if ( ! $user ) {
			$username = $this->signup_prefix . $emplid;
			$fragment = $this->create_temp_signup( $emplid );
		} else {
			$username = $user->user_login;
			$fragment = substr( $user->user_pass, 8, 4 );
		}

		if ( ! $fragment ) {
			$this->handle_error( 'No signup record found.', 403 );
		}

		// The user is now authorized to register.
		$this->set_sso_authorization_cookie( $username, $fragment );

		// If this is still a temporary signup, redirect to the registration page.
		if ( substr( $username, 0, strlen( $this->signup_prefix ) ) === $this->signup_prefix ) {
			wp_safe_redirect( home_url( 'register' ) );
			exit;
		}

		// This is a fully registered user. Log them in.
		$this->set_sso_authentication_cookie( $user );
		wp_safe_redirect( home_url() );
		exit;
	}

	/**
	 * Clear the SSO authorization cookie.
	 */
	public function clear_sso_authorization_cookie(): void {
		setcookie( $this->cookie_name, '', time() - 3600, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN, true, true );
		setcookie( $this->cookie_name, '', time() - 3600, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, true, true );
	}

	/**
	 * Set a cookie when a user is authorized to register via CUNY SSO.
	 *
	 * @param string $username The username of the user.
	 * @param string $fragment A secret salt to use in cookie generation.
	 */
	private function set_sso_authorization_cookie( string $username, string $fragment ): void {

		$expiration = time() + 7 * DAY_IN_SECONDS;

		// We need to specify a token so that the WP session manager does not store
		// something, but we may also want to think about harnessing that. We'll see.
		$token = 'abcdefg';

		$key = wp_hash( $username . '|' . $fragment . '|' . $expiration . '|' . $token, 'auth' );

		$hash = hash_hmac( 'sha256', $username . '|' . $expiration . '|' . $token, $key );

		$cookie_value = $username . '|' . $expiration . '|' . $token . '|' . $hash;

		setcookie( $this->cookie_name, $cookie_value, $expiration, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN, true, true );
		setcookie( $this->cookie_name, $cookie_value, $expiration, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, true, true );
	}

	/**
	 * Set a cookie when a user has registered and authenticated via CUNY SSO.
	 *
	 * @param WP_User $user The user for whom to set an authentication cookie.
	 */
	public function set_sso_authentication_cookie( WP_User $user ): void {
		wp_set_auth_cookie( $user->ID, true, is_ssl() );
	}

	/**
	 * Get a user by their CUNY EMPLID.
	 *
	 * @param string $emplid The CUNY EMPLID.
	 * @return WP_User|false A matching user, or false if none found.
	 */
	private function get_user( string $emplid ) {
		$users = get_users(
			array(
				'meta_key'   => 'cuny_sso_emplid',
				'meta_value' => $emplid,
			)
		);

		if ( empty( $users ) ) {
			return false;
		}

		return $users[0];
	}

	/**
	 * Provide a placeholder signup record for a user who is authorized via
	 * SSO, but not yet fully registered on the site.
	 *
	 * If the passed EMPLID has already been registered, return the existing
	 * activation key.
	 *
	 * This allows us to generate a secure authorization cookie by using much
	 * of WordPress core's built-in logic and the user account's password as a
	 * secret key.
	 *
	 * Once registration is complete, this signup record will be removed and
	 * the user's associated CUNY EMPLID will be stored as a full user's meta.
	 *
	 * @param string $emplid The CUNY EMPLID.
	 * @return string The activation key.
	 */
	private function create_temp_signup( string $emplid ): string {
		$signup       = $this->get_temp_signup( $emplid );
		$existing_key = $signup ? $signup->activation_key : '';

		if ( $existing_key ) {
			return $existing_key;
		}

		// Do not send an email for this signup.
		remove_action( 'after_signup_user', 'wpmu_signup_user_notification' );

		$sso_id = wp_generate_uuid4();

		wpmu_signup_user(
			$this->signup_prefix . $emplid,
			$emplid . '@example.com',
			array(
				'cuny_sso_initial' => $sso_id,
			)
		);

		// Restore the email notification.
		add_action( 'after_signup_user', 'wpmu_signup_user_notification', 10, 4 );

		$signup = $this->get_temp_signup( $emplid );

		return $signup ? $signup->activation_key : '';
	}

	/**
	 * Retrieve the activation key for a temporary signup record.
	 *
	 * @param string $emplid The CUNY EMPLID.
	 * @return stdClass|false The signup record. False if none found.
	 */
	public function get_temp_signup( string $emplid ) {
		global $wpdb;

		if ( 0 !== strpos( $emplid, $this->signup_prefix ) ) {
			$username = $this->signup_prefix . $emplid;
		} else {
			$username = $emplid;
		}

		$signups = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->signups} WHERE user_login = %s",
				$username
			)
		);

		if ( ! $signups ) {
			return false;
		}

		return $signups[0];
	}
}
