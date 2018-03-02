
# Pwned Password Checker

_Updated 3rd March, 2018 GMT +11_

WordPress plugin that checks the password a user enters on registration, reset or profile update to see if it's been 'burned' ( released in a public database breach of another website or obtained through other means and made public ) using [Have I Been Pwned's _PwnedPasswords_ API](https://haveibeenpwned.com/API/v2).

### Breakdown
1. A user enters a password to login, reset or change their password - which triggers the following WordPress hooks: `'user_profile_update_errors'`, `'registration_errors'` or `'validate_password_reset'`
2. The plugin checks for a `transient_key` to see if a request is already in progress to the Have I Been Pwned API _(which limits 1 request every 1.5 seconds from a single IP)_
   * If there's already a request in progress, the plugin waits 2 seconds and tries again.
   * Upon the second try, the plugin returns `false` and logs an error to the error_log. The user will be allowed to set the password they entered, and _the password will not have been checked._
   * If there is not other request in progress, the plugin begins a request and sets a `transient_key` to prevent other requests occuring in the meantime.
3. The password the user entered is hashed using SHA1. Then the first five characters hash are sent to _Have I Been Pwned?_, in a technique referred to as [k-anonymization](https://en.wikipedia.org/wiki/K-anonymity).
   * As an example, the word _`password`_ when hashed, is `5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8`
   * In other words, the password is converted to a form that's hard to reverse
   * Then it's trimmed down to the first five characters: `5BAA6`
   * And is sent to _Have I Been Pwned?_ to check their comprehensive database.
5. _Have I Been Pwned?_ responds with a list of passwords with the same first characters and _PwnedPasswordChecker_ then looks at the list to see if the password is there.
6. If the password is found in the list an error message is shown to the user and they are informed that the password has been breached:

>That password is not secure.  
If you use that password on other sites,
you should _change it immediately_
Please enter a different password.
[Learn more](https://haveibeenpwned.com/Passwords)

### Installation
- Download and place in a new folder within the `/wp-content/plugins` directory
- Activate via wp-admin, drink lemonade.

### Todos
 - Get a few people to double-check my code and call me names.
 - Possibly find a better method of returning an issue to the user if Have I Been Pwned cannot be reached or limits are met.
 - Allow for checking of burned passwords completely locally without an external GET request.  Wouldn't be great for plugin-download-size though and would require a more manual install process.
 ~~- Should probably use CURL instead of file_get_contents, although the latter is more likely to be available on shared hosting.~~
 ~~- Replace the switch method with something else for the sake of replacing the switch method with something else.~~

### Cautions
This obviously isn't perfect. Too many requests or a server outage will return false and allow the user to set the password even if it's burned. This plugin should be used _alongside a strong password policy_ as a second line of defence.

In the event that Have I Been Pwned were ever itself, _pwned_ - this plugin could end up sending requests to an unwanted recipient. I have taken some precautions to verify that the request is going to the _right place_, by communicating with the API over a secure connection and limiting what Certificate Authorities are accepted when verifying the domain name, but all these precautions don't help if the _right place_ is itself compromised. I'd recommend following [HIBP on social media](https://twitter.com/haveibeenpwned) so you'll be able to act if it ever happens.

Also, as much as the k-anonymity model, is a nifty way of limiting what's being sent to external servers - it's more or less _security through obscurity_. Narrowing down which password is yours on a list of similar passwords may be easier than you think. Even though the passwords on _Have I Been Pwned_ are hashed, it's important to note that the SHA1 algorithm was [cracked by Google in early 2017](https://www.theverge.com/2017/2/23/14712118/google-sha1-collision-broken-web-encryption-shattered).

### Thanks to
* [Troy Hunt](https://www.troyhunt.com/) - For creating [a service that let's people know if they've been pwned](https://haveibeenpwned.com) and for [perpetuating positive Australian stereotypes](https://www.youtube.com/watch?v=WbyN8CiM2rQ) ;)
* [Joe Sexton](http://www.webtipblog.com/force-password-complexity-requirements-wordpress/) - For posting a great breakdown of WordPress password update hooks along with code which I have shamelessly adapted.
* [smakofsky](https://github.com/smakofsky/) - Who inadvertedly informed me of an API update when he posted about [his own Pwned Passwords implementation](https://github.com/smakofsky/pwndpwd/) on Twitter.

Now that you've read this, you may as well go download [WordFence](https://www.wordfence.com/) instead given that it does what this plugin does, isn't coded by a dingus and has other WordPress-hardening features included to make your site a fortress, or something.
