1. API RESTful para Gerenciamento de autenticaçãao
•	Descrição: Crie uma API para gerenciar autenticação de bearer token.
•	Tecnologias: PHP (Laravel), MySQL, JWT para autenticação.
•	Desafios: Implementar validações de dados, middleware para segurança, e documentação da API com Swagger.
•   Metodos: Login, Register, Refresh token, logout, me.


Install via composer
Run the following command to pull in the latest version:
composer require tymon/jwt-auth

Publish the config
Run the following command to publish the package config file:

php artisan vendor:publish --provider="Tymon\JWTAuth\Providers\LaravelServiceProvider"
You should now have a config/jwt.php file that allows you to configure the basics of this package.

Generate secret key
I have included a helper command to generate a key for you:

php artisan jwt:secret
This will update your .env file with something like JWT_SECRET=foobar

It is the key that will be used to sign your tokens. How that happens exactly will depend on the algorithm that you choose to use.


Update your User model
Firstly you need to implement the Tymon\JWTAuth\Contracts\JWTSubject contract on your User model, which requires that you implement the 2 methods getJWTIdentifier() and getJWTCustomClaims().

The example below should give you an idea of how this could look. Obviously you should make any changes, as necessary, to suit your own needs.

<?php

namespace App;

use Tymon\JWTAuth\Contracts\JWTSubject;
use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable implements JWTSubject
{
    use Notifiable;

    // Rest omitted for brevity

    /**
     * Get the identifier that will be stored in the subject claim of the JWT.
     *
     * @return mixed
     */
    public function getJWTIdentifier()
    {
        return $this->getKey();
    }

    /**
     * Return a key value array, containing any custom claims to be added to the JWT.
     *
     * @return array
     */
    public function getJWTCustomClaims()
    {
        return [];
    }
}
Configure Auth guard
Note: This will only work if you are using Laravel 5.2 and above.

Inside the config/auth.php file you will need to make a few changes to configure Laravel to use the jwt guard to power your application authentication.

Make the following changes to the file:

'defaults' => [
    'guard' => 'api',
    'passwords' => 'users',
],

...

'guards' => [
    'api' => [
        'driver' => 'jwt',
        'provider' => 'users',
    ],
],

Here we are telling the api guard to use the jwt driver, and we are setting the api guard as the default.

We can now use Laravel's built in Auth system, with jwt-auth doing the work behind the scenes!

Add some basic authentication routes
First let's add some routes in routes/api.php as follows:


Route::prefix('auth')->group(function ($router) {
    Route::post('login',[AuthController::class, 'login']);
    Route::post('register',[AuthController::class, 'register']);
});

Route::middleware(['auth:api'])->prefix('auth')->group(function ($router) {
    Route::post('logout',[AuthController::class, 'logout']);
    Route::post('refresh', [AuthController::class, 'refresh']);
    Route::get('me', [AuthController::class, 'me']);
});



<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Js;

class AuthController extends Controller
{
    public function __construct()
    {
        // $this->middleware('auth:api', ['except' => ['login']]);
    }

    public function register (Request $request){

        $validation = $request->validate([
            'name' => ['required'],
            'email' => 'email|unique:users',
            'password' => ['required']
        ]);

        $passoed = Hash::make($validation['password']);

        $user = User::create([
            'name' => $validation['name'],
            'email' => $validation['email'],
            'password' => $passoed,
        ]);

        return response()->Json([
            $user
        ]);
    }
    public function login()
    {
        $credentials = request(['email', 'password']);

        if (! $token = Auth::attempt($credentials)) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->respondWithToken($token);
    }
    public function me()
    {
        return response()->json(auth()->user());
    }
    public function logout()
    {
        auth()->logout();

        return response()->json(['message' => 'Successfully logged out']);
    }
    public function refresh()
    {
        return $this->respondWithToken(auth()->refresh());
    }
    protected function respondWithToken($token)
    {
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60
        ]);
    }
}