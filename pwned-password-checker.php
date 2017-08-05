<?php
/*

Plugin Name: Pwned Password Checker
Plugin URI: https://github.com/BenjaminNelan/PwnedPasswordChecker
Description: Checks a password via Have I Been Pwned to see if it's been burned.
Version:     1.0
Author: Benjamin Nelan
Author URI: https://benjaminnelan.com.au
Text Domain: pwned_password_checker
Text Domain: Domain Path: /locale
License:     GPL-2.0+
License URI: http://www.gnu.org/licenses/gpl-2.0.txt

=================================================================================
Thanks to Joe Sexton for his awesome post on WordPress password hooks.
http://www.webtipblog.com/force-password-complexity-requirements-wordpress/
=================================================================================

*/

if ( ! defined( 'ABSPATH' ) ) exit;

class PwnedPasswordChecker{

  // Have I Been Pwned SSL Info --
  // SHA1 Fingerprint to be used to make sure the GET request goes to the right place.
  private $cert_fingerprint = "da7aa027c5b50d3041200ce1482c9498e2f1701d";

  // CERTIFICATE expiry, so we can display a notice to update the fingerprint.
  private $cert_expires = "14-12-2018";

  // API URL
  private $haveibeenpwned = "https://haveibeenpwned.com/api/v2/pwnedpassword/";

  /**
   * plugin construct
   */
  function __construct(){
    // Check to see if the SSL fingerprint is about to expire
    // Probably way better ways of doing this.
    if ( strtotime('now + 14 days') > strtotime($this->cert_expires) ){
      add_action( 'admin_notices', function(){
        echo '<div class="notice notice-warning"><p>';
        _e( "Pwned Password Checker's SSL fingerprint is going to expire soon!", 'pwned_password_checker' );
        echo '</p></div>';
      });
    }

    // Register WordPress Hooks
    add_action( 'user_profile_update_errors', [ $this, 'check_for_burned_password' ], 10, 3 );
    add_filter( 'registration_errors', [ $this, 'check_for_burned_password' ], 10, 3 );
    add_action( 'validate_password_reset', [ $this, 'check_for_burned_password' ], 10, 2 );
  }

  /**
   * password_is_burned
   *
   * @author  Benjamin Nelan <hey@benjaminnelan.com.au>
   * @param   string $password
   * @param   int $attempt
   * @return  boolean
   */
  function password_is_burned( $password, $attempt = 0){

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
        $output = password_is_burned( $password, $attempt );
      } else {

        // Log the error
        error_log("Have I Been Pwned - Tried $attempt times to check password but other requests in progress.");
      }
    } else {

      // Decided to remove this, but will leave it commented in case I want it later
      // Check to see if the password string is already a sha1:
      // ( ctype_xdigit( $password ) && strlen( $password ) == 40 )

      // Get the SHA1 key of the password.
      $password_sha = sha1($password);

      // For sites with lots of users, probably unnecessary
      // Requests are limited to 1 every 1.5 seconds from the same IP
      if( function_exists('set_transient') ){
        set_transient( "PWNED_PASSWORD_REQUEST", "CHECKING_PASSWORD", 2 );
      }

      // Prepare our request with user agent and ssl requirements
      $options  = [
        'ssl'   => [
          'verify_peer' => true,
          'verify_peer_name' => true,
          'peer_fingerprint'  => $this->cert_fingerprint
        ],
        'http' => [
          'method' => 'POST',
          'header'  => 'Content-type: application/x-www-form-urlencoded',
          'content' => http_build_query([
            'Password' => $password_sha
          ]),
          'user_agent' => 'WordPress Plugin: Pwned Password Checker'
        ]
      ];

      $context = stream_context_create($options);

      // Reguest, supressing warning messages - we'll handle those on our own.
      @file_get_contents($this->haveibeenpwned, false, $context, -1, 1);

      // Previous method via GET
      // @file_get_contents($this->haveibeenpwned.$password_sha, false, $context, -1, 1);

      // Check for response header and HTTP response header.
      if ( isset($http_response_header[0]) &&  preg_match( "#HTTP/[0-9\.]+\s+([0-9]+)#", $http_response_header[0], $status ) ){
        // Get the status number from the regex group.
        $status = intval($status[1]);

        // Repond based on the status code.
        switch($status){
          case 200:
            // "Ok — everything worked and there's a string array of pwned sites for the account"
            // This means the password has been compromised and is 'burned'
            $output = true;
            break;
          case 400:
            // "Bad request — the account does not comply with an acceptable format (i.e. it's an empty string)"
            error_log("Have I Been Pwned - 400 - Bad request");
            break;
          case 403:
            // "Forbidden — no user agent has been specified in the request"
            error_log("Have I Been Pwned - 403 - Forbidden");
            break;
          case 404:
            // "Not found — the account could not be found and has therefore not been pwned"
            // This is the result we want to see.
            break;
          case 429:
            // "Too many requests — the rate limit has been exceeded"
            error_log("Have I Been Pwned - 429 - Too many requests");

            // We'll give it another shot...
            if($attempt < 2){
              // Increment the attempts to check the password
              $attempt++;
              error_log("Have I Been Pwned - 429 - Attempt #$attempt, Trying again...");

              // Wait to seconds and try again.
              sleep(2);
              $output = password_is_burned( $password, $attempt );
            } else {

              // Log the error
              error_log("Have I Been Pwned - Tried $attempt times to check password but error 429 persisted.");
            }

            break;
          default:
            // Some other error code, something bizarre going on.
            error_log("Have I Been Pwned - $status - Unknown issue.");
            break;
        }
      }
    }

    return $output;
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
      $message = ['<strong>ERROR</strong>:'];
      $message[] = 'The password you have entered has appeared in a public data breach of another website.';
      $message[] = 'It is not safe to use this password to protect your account, please choose another password.';
      $message[] = 'For more info, check out <a target="_blank" href="https://haveibeenpwned.com/Passwords" title="Have I Been Pwned">Have I Been Pwned</a>.';
      $errors->add( 'pass', join( ' ', $message ) );
    }

  	return $errors;
  }

}

$PwnedPasswordChecker = new PwnedPasswordChecker();
