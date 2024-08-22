<?php
/**
 * Template for the SSO registration form.
 *
 * @package sps-cbox-sso
 */

use SPS\CBOX\SSO\Config;

?>
<div class="col-sm-18">

	<div class="page" id="register-page">

		<div id="openlab-main-content"></div>

		<div class="entry-title">
			<h1><?php esc_html_e( 'Create an Account', 'commons-in-a-box' ); ?></h1>
		</div>

		<p>To create an account, please login with your CUNY credentials.</p>

		<a class="btn btn-primary" href="<?php echo esc_url( Config::login_url() ); ?>">Login with CUNY SSO</a>

	</div>

</div>
