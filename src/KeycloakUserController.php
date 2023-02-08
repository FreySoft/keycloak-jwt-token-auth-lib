<?php

namespace KeycloakGuard;

use App\Models\User;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Support\Facades\DB;
use Illuminate\Http\Request;
use KeycloakGuard\Exceptions\TokenException;
use KeycloakGuard\Exceptions\UserNotFoundException;
use KeycloakGuard\Exceptions\ResourceAccessNotAllowedException;

use App\Common\AppConst;
use App\Logger\Facades\Logger;
use App\Logger\Facades\AppLog;
use App\Http\Controllers\KeycloakAdminController;

class KeycloakUserController
{
    private $decodedToken;
    private $keycloakAdminController;

    public function __construct($token = null)
    {
        // parsed JWT token (from frontend <- from Keycloak)
        $this->decodedToken = $token;
    }



    /**
     * Create new User & store into users DB of App
     *
     * @param $user
     * @return $user
    */
    public function createUser($user)
    {
        // email & verified state
        $user->email = $this->decodedToken->email;
        $user->email_verified_at = date('Y-m-d H:i:s');

        // name
        $user->name = $this->decodedToken->given_name?:substr($this->decodedToken->name,0,strpos($this->decodedToken->name,' '));
        $user->surname = $this->decodedToken->family_name?:substr($this->decodedToken->name,strpos($this->decodedToken->name,' ')+1);

        // locales
        $user->locale = 'en';
        $user->locale_templates = 'en';

        // wait a little before check in -- 1-3 seconds
        // cause a couple of concurrency requests can come in same time
        sleep(2);

        // check if concurrency queries already saved a new User
        // return before saving
        if (DB::table(AppConst::USERS_TABLE_NAME)->where('email', $user->email)->exists()) {
            return $user;
        }

        // pass
        $newPassword = substr($this->decodedToken->sid,0,6);
        $user->password = bcrypt($newPassword);

        // create User if none
        try {
            $user = User::updateOrCreate(
                [
                    'email' => $user->email
                ],
                [
                    'updated_at' => date('Y-m-d H:i:s'),
                ]
            );

            //$user->save();

            //
            $user_id = (int)$user->getKey();

            // app log User
            AppLog::add('user', $user_id, 'create');
        }
        // something went wrong while
        catch (\Throwable $e) {
            Logger::error($e->getMessage(), $e->getTrace());
        }

        // return plain-text password (realtime once) back
        // for adding to Keycloak on next steps
        $user->password = $newPassword;

        return $user;
    }



    /**
     * Create new User in Keycloak auth DB
     *
     * @param $user
     * @return bool
    */
    public function createKeycloakUser($user): bool
    {
        $added_to_keycloak = false;

        // create with User model
        try {
            // Keycloak admin client <- API access
            $this->keycloakAdminController = new KeycloakAdminController();
            $keycloakClient = Keycloak\Admin\KeycloakClient::factory($this->keycloakAdminController->getParams());
            $this->keycloakAdminController->setClient($keycloakClient);

            if ( $this->keycloakAdminController->register( $this->prepareUserData($user) ) )
            {
                // app log User
                AppLog::add('user', $user->id, 'keycloak');

                return true;
            }
        }
        // something went wrong while
        catch (\Exception $e) { // \Illuminate\Database\QueryException $e
            Logger::error($e->getMessage(), $e->getTrace());
        }

        return false;
    }



    /**
     * Creating array from User's attributes
     *
     * @param $user
     * @return array
    */
    protected function prepareUserData($user): array
    {
        $ret = [];

        $ret['email'] = $user->email;
        $ret['password'] = $user->password;
        $ret['name'] = $user->name.' '.$user->surname;

        return $ret;
    }
}
