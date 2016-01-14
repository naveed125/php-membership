[![Build Status](https://travis-ci.org/naveed125/php-membership.png)](https://travis-ci.org/naveed125/php-membership)

# php-membership
A simple user management library that supports things like signin, sign-out, sign-up, forgot-password and email-verification.

## Example:
```
$membership = new Membership();
list($success, $result) = $membership->login($email, $pswd);
```