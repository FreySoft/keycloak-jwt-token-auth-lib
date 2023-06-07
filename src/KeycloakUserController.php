<?php

namespace KeycloakGuard;

use App\Common\AppConst;
use App\Http\Controllers\KeycloakAdminController;
use App\Logger\Facades\AppLog;
use App\Logger\Facades\Logger;
use App\Models\User;
use Illuminate\Support\Facades\DB;

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
     * @param $class
     * @return User $user
     */
    public function createUser($class)
    {
        $user = [];
        // email & verified state
        $user['email'] = $this->decodedToken->email;
        $user['email_verified_at'] = date('Y-m-d H:i:s');

        $name = !empty($this->decodedToken->name)
            ? $this->decodedToken->name
            : str_replace('@', ' ', $this->decodedToken->email);

        // name
        $user['name'] = $this->decodedToken->given_name
            ?: substr($name, 0, strpos($name, ' '));

        $user['surname'] = $this->decodedToken->family_name
            ?: substr($name, strpos($name, ' ') + 1);

        // pass
        $newPassword = substr($this->decodedToken->sid, 0, 6);
        $user['password'] = bcrypt($newPassword);
        $user['rainex_id'] = \Str::uuid();

        // create User if none
        DB::table(AppConst::USERS_TABLE_NAME)->insert($user);

        return $class->where('email', $user['email'])->first();
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

            if ($this->keycloakAdminController->register($this->prepareUserData($user))) {
                // app log User
                AppLog::add('user', $user->id, 'keycloak');

                return true;
            }
        } // something went wrong while
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
        $ret['name'] = $user->name . ' ' . $user->surname;

        return $ret;
    }
}
