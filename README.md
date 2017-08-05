# Pwned Password Checker

WordPress plugin that checks the password a user enters on registration, reset or profile update to see if it's been 'burned' (released in a public database breach of another website) using [Have I Been Pwned's API](https://haveibeenpwned.com/API/v2).

### Breakdown
1) A user enters a password to set for their account and triggers one of the WordPress hooks: `'user_profile_update_errors'`, `'registration_errors'` or `'validate_password_reset'`
2) The plugin checks for a `transient_key` to see if a request is already in progress to the Have I Been Pwned API _(which limits 1 request every 1.5 seconds from a single IP)_
-- If there's already a request in progress, the plugin waits 2 seconds and tries again.
-- Upon the second try, the plugin returns `false` and logs an error to the error_log. The user will be allowed to set the password they entered, and _the password will not have been checked._
3) A SHA1 hash of the password is made and is sent via a GET request to _Have I Been Pwned?_
4) The response headers are read from the request and behaves based on the status code.
-- 200 _( Success )_ = Returns `true`, this means that password has been burned.
-- 429 _( Too many requests )_ = Waits for 2 seconds then tries again, giving up on the second attempt if it also fails and logging an error via error_log. This will return `false` if both attempts fail.
-- Other errors = Returns `false`, and logs an error via error_log.
5) Upon returning `true`, an error message is shown to the user and they are informed that the password has been breached:

>>'The password you have entered has appeared in a public data breach of another website. It is not safe to use this password to protect your account, please choose another password. For more info, check out [Have I Been Pwned](https://haveibeenpwned.com).'

### Installation
- Download and place in a new folder within the `/wp-content/plugins` directory
- Activate via wp-admin, drink lemonade.

### Todos
 - Get a few people to double-check my code and call me names.
 - Should probably use CURL instead of file_get_contents, although the latter is more likely to be available on shared hosting.
 - Possibly find a better method of returning an issue to the user if Have I Been Pwned cannot be reached or limits are met.
 - Replace the switch method with something else for the sake of replacing the switch method with something else.
 - Download the SHA1 database and allow for checking of burned passwords without an external GET request.  Wouldn't be great for plugin-download-size though and would require a more manual install process.

### Cautions
This obviously isn't perfect, as an error resulting from too many requests or a server outage will return false - and allow the user to set the password even if it's burned. This plugin should be used _alongside a strong password policy_ as a second line of defence.

This plugin sends a SHA1 hash of the password over HTTPS when checking against the HIBP API. However, in the event that Have I Been Pwned were ever itself, _pwned_ - this plugin could end up sending requests to an unwanted receipient. It's important to note that the SHA1 algorithm was [cracked by Google in early 2017](https://www.theverge.com/2017/2/23/14712118/google-sha1-collision-broken-web-encryption-shattered) and it's possible that the password could be figured out by someone with enough computing power. I have taken some precautions to verify that the request is going to the _right place_, by checking the SSL fingerprint of site, but that doesn't help if the _right place_ is itself compromised. I'd recommend following [HIPB on social media](https://twitter.com/haveibeenpwned) so you'll be able to act if it ever happens.

### Thanks to
* [Joe Sexton](http://www.webtipblog.com/force-password-complexity-requirements-wordpress/) - For posting a great breakdown of WordPress password update hooks along with code which I have shamelessly adapted
* [Troy Hunt](https://www.troyhunt.com/) - For creating [a service that let's people know if they've been pwned](https://haveibeenpwned.com) and for [perpetuating positive Australian stereotypes](https://www.youtube.com/watch?v=WbyN8CiM2rQ) ;)

_5th August, 2017_
