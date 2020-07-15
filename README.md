<h1 align="center">Socialite - Apple Helper</h1>
<p align="center">
<a href="https://packagist.org/packages/ahilmurugesan/socialite-apple-helper"><img src="https://poser.pugx.org/ahilmurugesan/socialite-apple-helper/d/total.svg" alt="Total Downloads"></a>
<a href="https://packagist.org/packages/ahilmurugesan/socialite-apple-helper"><img src="https://poser.pugx.org/ahilmurugesan/socialite-apple-helper/v/stable.svg" alt="Latest Stable Version"></a>
<a href="https://packagist.org/packages/ahilmurugesan/socialite-apple-helper"><img src="https://poser.pugx.org/ahilmurugesan/socialite-apple-helper/license.svg" alt="License"></a>
</p>

---

## 1. Installation

```bash
// This assumes that you have composer installed globally
composer require YermolaievDmytro/socialite-apple-helper
```

## 2. Configuration Setup

You will need to add an entry to the services configuration file so that after config files are cached for usage in production environment (Laravel command `artisan config:cache`) all config is still available.

To set up the required environment variables you can use the following artisan command which comes with this package. 

```
php artisan socialite:apple
```

The command will prompt you the required values.You need to provide the following keys.
 1. Team ID
 2. Key ID
 3. Client ID
 4. Auth Key ( file name of p8 auth file, located inside storage/app/ ) Example: AuthKey_SAMPKEY.p8
 5. Redirect URI ( fully qualified secure callback url ) Example: https://website.com/socialite/apple/callback
 6. Token Refresh Interval ( in days )

Client Secret will be automatically generated and added to the .env file by using the above command. 

> The expiration time registered claim key, the value of which must not be greater than 15777000 (6 months in seconds) from the Current Unix Time on the server.

[Sign in with Apple](https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens) Client Secret expiration time cannot be greater than six months. Hence it is advisible to refresh the Client Secret atleast once in six months after creation. You can adjust the Token Refresh Interval. There is a scheduled task which comes along with this package which will ensure that the Client Token is refreshed automatically. Please do ensure that you have enabled [Task Scheduling](https://laravel.com/docs/master/scheduling#introduction)

To manually refresh the Client Secret, please run the following command
```
php artisan socialite:apple --refresh
```

## 3. Demo Repo
* [Demo Repo](https://github.com/VonecTechnologies/socialite-apple-sample/)
