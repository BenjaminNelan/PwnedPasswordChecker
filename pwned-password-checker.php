<?php
/*

Plugin Name: Pwned Password Checker
Plugin URI: https://github.com/BenjaminNelan/PwnedPasswordChecker
Description: Checks a password via Have I Been Pwned to see if it's been burned.
Version:     1.1
Author: Benjamin Nelan
Author URI: https://benjaminnelan.com.au
Text Domain: pwned_password_checker
Text Domain: Domain Path: /locale
License:     GPL-2.0+
License URI: http://www.gnu.org/licenses/gpl-2.0.txt

=================================================================================
Thanks to Troy Hunt for the incredible API service used by this plugin.
https://www.troyhunt.com/

Thanks to Joe Sexton for his awesome post on WordPress password hooks.
http://www.webtipblog.com/force-password-complexity-requirements-wordpress/
( Psst Joe, if you're reading this, https! )

Thanks to smakofsky who inadvertedly informed me of an API update.
https://github.com/smakofsky/pwndpwd/
=================================================================================

*/

if ( ! defined( 'ABSPATH' ) ) exit;

class PwnedPasswordChecker{

  // Have I Been Pwned SSL Info --
  // SHA1 Fingerprint to be used to make sure the GET request goes to the right place.
  // private $cert_fingerprint = "da7aa027c5b50d3041200ce1482c9498e2f1701d";

  // CERTIFICATE expiry, so we can display a notice to update the fingerprint.
  // private $cert_expires = "14-12-2018";

  // API URL
  private $haveibeenpwned = "https://api.pwnedpasswords.com/range/";

  // Settings
  // We'll attach these to an options page later.
  private $check_on_login = true;
  private $check_on_signup = true;
  private $check_on_reset = true;
  private $check_on_change = true;

  // Email Test
  private $email_failed = false;

  // Notices
  private $notices = [];

  /**
   * plugin construct
   */
  function __construct(){

    // -- Check to see if the SSL fingerprint is about to expire
    // if ( strtotime('now + 28 days') > strtotime($this->cert_expires) ){
    //
    //   // Let admin users know via a notice.
    //   self::add_notice( "SSL fingerprint is going to expire soon!" );
    //
    // }

    // -- Check for openssl for use with tls verification
    if( !extension_loaded('openssl') ){

      // No OpenSSL
      self::add_notice( "Can't verify certificates because the OpenSSL module is not loaded." );
      return;

    }

    // -- Check for curl for querying the url
    if( !extension_loaded('curl') ){

      // No curl
      self::add_notice( "Can't check PwnedPasswords because the Curl module is not loaded." );
      return;

    }

    // -- Check that openssl is installed properly
    // $cert_loc = function_exists('openssl_get_cert_locations') ? openssl_get_cert_locations() : false;
    // if( !$cert_loc || isset($cert_loc['default_cert_file']) && !file_exists($cert_loc['default_cert_file']) ){
    //
    //   die('Cert location doesn\' exist');
    //   // Certificates
    //   self::add_notice("Can't verify certificates because the OpenSSL module is not installed properly." );
    //   return;
    // }

    // -- WordPress Hooks
    // # Check on Registration
    if( $this->check_on_signup ) add_filter( 'registration_errors', [ $this, 'check_for_burned_password' ], 1000, 3 );

    // # Check on Profile
    if( $this->check_on_change ) add_action( 'user_profile_update_errors', [ $this, 'check_for_burned_password' ], 1000, 3 );

    // # Check on Reset
    if( $this->check_on_reset ) add_action( 'validate_password_reset', [ $this, 'validate_password_reset' ], 1000, 2 );

    // # Check on Login
    if( $this->check_on_login ) add_action( 'authenticate' , [ $this, 'check_on_authenticate' ], 1000, 3 );
  }

  /**
   * password_is_burned
   *
   * @author  Benjamin Nelan <hey@benjaminnelan.com.au>
   * @param   string $password
   * @param   int $attempt
   * @return  boolean
   */
  function password_is_burned( $password, $attempt = 0 ){

    $output = false;
    $attempt = intval($attempt);

    // Try to account for sites with lots of users
    // See if a request has just been made, wait and try again
    if ( function_exists('get_transient') && get_transient( "PWNED_PASSWORD_REQUEST" ) !== false) {
      if($attempt < 2){

        // Increment the attempts to check the password
        $attempt++;
        error_log("Have I Been Pwned - Attempt #$attempt, waiting for previous request to finish.");

        // Wait two seconds and try again
        sleep(2);
        $output = self::password_is_burned( $password, $attempt );

      } else {

        // Log the error
        error_log("Have I Been Pwned - Tried $attempt times to check password but other requests in progress.");

      }
    } else {

      // Decided to remove this, but will leave it commented in case I want it later
      // Check to see if the password string is already a sha1:
      // ( ctype_xdigit( $password ) && strlen( $password ) == 40 )

      // Get the SHA1 key of the password.
      $password_sha = strtoupper( hash( 'sha1', $password ) );
      $k_anon_hash = substr( $password_sha, 0, 5 );

      // For sites with lots of users, probably unnecessary
      // Requests are limited to 1 every 1.5 seconds from the same IP
      if( function_exists('set_transient') ){
        set_transient( "PWNED_PASSWORD_REQUEST", "CHECKING_PASSWORD", 2 );
      }

      // Since the PwnedPasswords API uses Comodo for TLS, we will only allow root certificates signed by Comodo.
      // Could use WordPress's 'plugin_dir_path' but will keep this vanilla PHP in case I want to use it elsewhere.
      $root_certificates = dirname(__FILE__).DIRECTORY_SEPARATOR.'certs.pem';

      // Prepare our request with user agent and ssl requirements
      $ch = curl_init();
      curl_setopt( $ch, CURLOPT_URL, $this->haveibeenpwned.$k_anon_hash );
      curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, TRUE );
      curl_setopt( $ch, CURLOPT_SSL_VERIFYHOST, 2 );
      curl_setopt( $ch, CURLOPT_RETURNTRANSFER, TRUE );
      curl_setopt( $ch, CURLOPT_CAINFO, $root_certificates );
      curl_setopt( $ch, CURLOPT_HTTPHEADER, [ 'method' => 'GET' ] );
      curl_setopt( $ch, CURLOPT_TIMEOUT, 10 );
      // if( defined('CURLOPT_CERTINFO') ) curl_setopt( $ch, CURLOPT_CERTINFO, TRUE );
      $response = curl_exec($ch);
      // if( defined('CURLINFO_CERTINFO') ) var_dump( curl_getinfo($ch, CURLINFO_CERTINFO) );
      curl_close($ch);

      // Is this password on the list?
      if( strpos( $response, substr( $password_sha, 5 ) ) !== false ){
        $output = true;
      }

    }

    return $output;
  }

  /**
   * check_on_authenticate
   *
   * @author  Benjamin Nelan
   * @param   WP_User $user
   * @param   string $username
   * @param   string $password
   * @return  null
   */
  function check_on_authenticate($user = null, $username, $password){

    // If username or password are empty, don't continue.
    if( empty($username) || empty($password) ) return;

    // Check that our credentials are for real.
    $login = wp_authenticate_username_password(null, $username, $password);

    // User credentials are accurate, now let's see if the password is burned.
    if ( !is_wp_error( $login ) && self::password_is_burned( $password ) ){

      // Dummy WP_Die function to stop 'retreive_password()' from exiting the script.
      // If we can't reset the user's password, we won't. Let them login, then notify them.
      add_filter( 'wp_die_handler', function(){ return [$this, 'authenticate_die']; }, 10, 1 );

      // TODO
      // We'll be using a function that only exists in wp-login.
      // Our reset email unfortunately won't be set unless the function exists.

      // Fudge our way along with the native 'retrieve_password()' function by setting $_POST manually
      $_POST['user_login'] = $username;

      // Attempt to send a password reset email to the user because their password is vulnerable.
      // This is a wp-login function and handles all the checking for us.
      $reset_success = (bool) ( function_exists( 'retrieve_password' ) && ( retrieve_password() === true ) );

      // Remove the filter just in case.
      remove_filter( 'wp_die_handler', [ $this, 'authenticate_die' ] );

      // Password is burned, and email was sent successfully.
      // TODO Not a fan of how I've done this. Will revist.
      if( $reset_success && !$this->email_failed ) {

        // Password reset email sent successfully.
        add_filter( 'login_errors', [ $this, 'login_errors' ], 10);

        // Prevent login by returning null
        return;
      }
    }

    // // Everything else passed, return user obj.
    return $user;
  }

  /**
   * authenticate_die
   * @author  Benjamin Nelan
   * Used during 'check_on_authenticate' and triggered if 'retreive_password' fails.
   */
  function authenticate_die(){
    $this->email_failed = true;
  }

  /**
   * login_errors
   * @author  Benjamin Nelan
   * @return  string
   * Used during 'check_on_authenticate' and displayed to the user if 'retreive_password' succeeds.
   */
  function login_errors(){
    $message = '<br><strong>Your password is not secure.</strong>';
    $message .= '<p style="margin-bottom: 10px;">In order to protect your account, we have sent a password reset link to your email address.</p>';
    $message .= '<p style="padding: 1em 0;">If you use that password on other sites,<br> you should <i>change it immediately.</i></p>';
    $message .= '<small style="text-align:right;display:block"><a target="_blank" href="https://haveibeenpwned.com/Passwords" title="Have I Been Pwned">Learn more</a></small>';
    return $message;
  }

  /**
   * add_notice
   * @author  Benjamin Nelan
   * @param   string $msg
   * @return  void
   */

  function add_notice( $msg ){
    static $action = false;

    // Remember the notice for output
    $this->notices[] = $msg;

    // Add the action to display our notice(s) but only once.
    if( !$action ) add_action( 'admin_notices', [ $this, 'handle_notice' ] );
    $action = true;
  }

  /**
   * handle_notice
   * @author  Benjamin Nelan
   * @return  void
   */

  function handle_notice(){

    // Draw the notices
    echo '<div class="notice notice-warning">';
    echo '<p>';
    echo '<small>PwnedPasswordChecker: </small><br>';
    foreach( $this->notices as $notice ){
      esc_html_e( $notice, 'pwned_password_checker' ).'<br>';
    }
    echo '</p>';
    echo '</div>';

  }

  // ==============================================================================
  // Now time to use some code by Joe Sexton from WebTipBlog to make this all work.
  // Cheers, Joe!
  // ==============================================================================

  /**
   * check_for_burned_password
   *
   * @original_author  Joe Sexton <joe.@webtipblog.com>
   * @butchered_by Benjamin Nelan
   * @param   WP_Error $errors
   * @return  WP_Error
   * Used on the 'resetpass' login page and wp-admin 'profile' page
   */
  function check_for_burned_password( WP_Error &$errors ) {

    // Get the password
  	$password = ( isset( $_POST[ 'pass1' ] ) && trim( $_POST[ 'pass1' ] ) ) ? $_POST[ 'pass1' ] : null;

  	// Check that the password isn't empty and that there aren't other errors already.
  	if ( empty( $password ) || ( $errors->get_error_data( 'pass' ) ) ){
      return $errors;
    }

    // Check the password via Have I Been Pwned
  	if ( self::password_is_burned( $password ) ){

      // Uh oh - pwned. Add as error.
      $message = '<br><strong>That password is not secure.</strong>';
      $message .= '<p style="padding: 1em 0;">If you use that password on other sites,<br> you should <i>change it immediately.</i></p>';
      $message .= 'Please enter a different password.';
      $message .= '<small style="text-align:right;display:block"><a target="_blank" href="https://haveibeenpwned.com/Passwords" title="Have I Been Pwned">Learn more</a></small>';
      $errors->add( 'pass', $message );

    }

  	return $errors;
  }

  /**
   * validate_password_reset
   * @param   object $errors
   * @param   WP_User|WP_Error $user
   * @return  WP_Error
   * Alias for check_for_burned_password that passes by reference.
   */
  function validate_password_reset( $errors, $user ) {
  	return self::check_for_burned_password( $errors );
  }

}

$PwnedPasswordChecker = new PwnedPasswordChecker();
