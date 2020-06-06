1. create migration for admin table

        php artisan make:model Admin -m


         Schema::create('admins', function (Blueprint $table) {
                    $table->increments('id');
                    $table->string('name');
                    $table->string('email')->unique();
                    $table->string('password');
                    $table->rememberToken();
                    $table->timestamps();
                });


2. make changes in Admin model in app/Admin.php


        <?php

        namespace App;

        use Illuminate\Notifications\Notifiable;
        use Illuminate\Foundation\Auth\User as Authenticatable;
        use App\Notifications\AdminResetPasswordNotification;

        class Admin extends Authenticatable
        {

            use Notifiable;

            // declare guard type
            protected $guard = 'admin';

            /**
             * The attributes that are mass assignable.
             *
             * @var array
             */
            protected $fillable = [
                'name', 'email', 'password',
            ];

            /**
             * The attributes that should be hidden for arrays.
             *
             * @var array
             */
            protected $hidden = [
                'password', 'remember_token',
            ];


        }





2. create login page in view/authAdmin/login.php




            @extends('layouts.app')
            @section('content')
            <div class="container">
                <div class="row justify-content-center">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header">{{ __('Login') }}</div>

                            <div class="card-body">
                                <form method="POST" action="">
                                    @csrf

                                    <div class="form-group row">
                                        <label for="email" class="col-md-4 col-form-label text-md-right">{{ __('E-Mail Address') }}</label>

                                        <div class="col-md-6">
                                            <input id="email" type="email" class="form-control @error('email') is-invalid @enderror" name="email" value="{{ old('email') }}" required autocomplete="email" autofocus>

                                            @error('email')
                                                <span class="invalid-feedback" role="alert">
                                                    <strong>{{ $message }}</strong>
                                                </span>
                                            @enderror
                                        </div>
                                    </div>

                                    <div class="form-group row">
                                        <label for="password" class="col-md-4 col-form-label text-md-right">{{ __('Password') }}</label>

                                        <div class="col-md-6">
                                            <input id="password" type="password" class="form-control @error('password') is-invalid @enderror" name="password" required autocomplete="current-password">

                                            @error('password')
                                                <span class="invalid-feedback" role="alert">
                                                    <strong>{{ $message }}</strong>
                                                </span>
                                            @enderror
                                        </div>
                                    </div>

                                    <div class="form-group row">
                                        <div class="col-md-6 offset-md-4">
                                            <div class="form-check">
                                                <input class="form-check-input" type="checkbox" name="remember" id="remember" {{ old('remember') ? 'checked' : '' }}>

                                                <label class="form-check-label" for="remember">
                                                    {{ __('Remember Me') }}
                                                </label>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="form-group row mb-0">
                                        <div class="col-md-8 offset-md-4">
                                            <button type="submit" class="btn btn-primary">
                                                {{ __('Login') }}
                                            </button>

                                            @if (Route::has('password.request'))
                                                <a class="btn btn-link" href="">
                                                    {{ __('Forgot Your Password?') }}
                                                </a>
                                            @endif
                                        </div>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            @endsection







3. create controller for admin login page in AuthAdmin/LoginController.php

                php artisan make:controller AuthAdmin/LoginController



                <?php

                namespace App\Http\Controllers\AuthAdmin;

                use App\Http\Controllers\Controller;
                use Illuminate\Http\Request;

                class LoginController extends Controller
                {
                    //

                    public function showLoginForm()
                    {
                        return view('authAdmin.login');
                    }

                }







4. create route for admin  login form  in route/web.php



		Route::prefix('admin')->group(function() {

			 Route::get('/login', 'AuthAdmin\LoginController@showLoginForm')->name('admin.login');
		}


5. create guard in config/auth.php

		add admin guard



			'guards' => [
		        'web' => [
		            'driver' => 'session',
		            'provider' => 'users',
		        ],

		        'api' => [
		            'driver' => 'token',
		            'provider' => 'users',
		        ],

		        'admin' => [
		            'driver' => 'session',
		            'provider' => 'admins',
		        ],
		    ],	



		    add admin in provider


		     'providers' => [
		        'users' => [
		            'driver' => 'eloquent',
		            'model' => App\User::class,
		        ],

		        'admins' => [
		            'driver' => 'eloquent',
		            'model' => App\Admin::class,
		        ],

		        
		    ],	


		add Resetting Passwords 

		'passwords' => [
		        'users' => [
		            'provider' => 'users',
		            'table' => 'password_resets',
		            'expire' => 60,
		        ],
		        'admins' => [
		            'provider' => 'admins',
		            'table' => 'password_resets',
		            'expire' => 60,
		        ],
		    ],



6. add constuctor function for middlewar of authenication in authAdmin/LoginController.php


         public function __construct()
            {
                $this->middleware('guest:admin')->except(['logout']);
            }


 7. Add LOgin Function in authAdmin/loginController.php


          public function login(Request $request)
            {
                $this->validate($request, [
                    'email' => 'required|email',
                    'password' => 'required|min:6'
                ]);

        $credential = [
            'email' => $request->email,
            'password' => $request->password
        ];

        // Attempt to log the user in
        if (Auth::guard('admin')->attempt($credential, $request->member)){
            // If login succesful, then redirect to their intended location
            return redirect()->intended(route('admin.home'));
        }

        // If Unsuccessful, then redirect back to the login with the form data
        return redirect()->back()->withInput($request->only('email', 'remember'));
    }  


8.Make dashboard page for redirecting after successfull login in view folder admin/home.blade.php


	
        @extends('layouts.app')

        @section('content')
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">Admin Dashboard</div>

                        <div class="card-body">
                            @if (session('status'))
                                <div class="alert alert-success" role="alert">
                                    {{ session('status') }}
                                </div>
                            @endif

                            You are logged in as Admin
                        </div>
                    </div>
                </div>
            </div>
            </div>
            @endsection


9. add new controller  for admindashboard redirect 

		php artisan make:controller AdminController

		<?php

        namespace App\Http\Controllers;

        use Illuminate\Http\Request;

        class AdminController extends Controller
        {
             public function __construct()
            {
                $this->middleware('auth:admin');
            }
            /**
             * Show the application dashboard.
             *
             * @return \Illuminate\Http\Response
             */
            public function index()
            {
                return view('admin.home');
            }
        }




9. add route for dashboard page after login  in


        Route::prefix('admin')->group(function() {
            Route::get('/', 'AdminController@index')->name('admin.home');
            Route::get('/login', 'AuthAdmin\LoginController@showLoginForm')->name('admin.login');
            Route::post('/login', 'AuthAdmin\LoginController@login')->name('admin.login.submit');
        });


10. add route in authAdmin/login.blade.php

		 <form method="POST" action="{{ route('admin.login.submit') }}">


11. add logout function in authAdmin/LoginController.php


          public function logout(Request $request)
        {
            Auth::guard('admin')->logout();

         //        $request->session()->invalidate();

            return redirect('/');
        }

 12. add route in web.php 


Route::prefix('admin')->group(function() {

//
   
    Route::post('/logout', 'AuthAdmin\LoginController@logout')->name('admin.logout');

   //
  
});

13. update some code in view/layouts/app.blade.php


		  @if(Auth::guard('admin')->check())

                          <li class="nav-item dropdown">
                                <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                                    {{ Auth::user()->name }} <span class="caret"></span>
                                </a>

                                <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                                    <a class="dropdown-item" href="{{ route('admin.logout') }}"
                                       onclick="event.preventDefault();
                                                     document.getElementById('admin-logout-form').submit();">
                                        {{ __('Logout') }}
                                    </a>

                                    <form id="admin-logout-form" action="{{ route('admin.logout') }}" method="POST" style="display: none;">
                                        @csrf
                                    </form>
                                </div>
                            </li>


                             @else

                             
                            <li class="nav-item dropdown">
                                <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                                    {{ Auth::user()->name }} <span class="caret"></span>
                                </a>

                                <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                                    <a class="dropdown-item" href="{{ route('logout') }}"
                                       onclick="event.preventDefault();
                                                     document.getElementById('logout-form').submit();">
                                        {{ __('Logout') }}
                                    </a>

                                    <form id="logout-form" action="{{ route('logout') }}" method="POST" style="display: none;">
                                        @csrf
                                    </form>
                                </div>
                            </li>

                             

                                @endif




                             


14. add  some code in Exception/Handler.php


        use Illuminate\Support\Arr;
        use Exception;
        //use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
        use Request;
        use Response;
        use Illuminate\Auth\AuthenticationException;


        protected function unauthenticated($request, AuthenticationException $exception)
            {
        //        return $request->expectsJson()
        //            ? response()->json(['message' => 'Unauthenticated.'], 401)
        //            : redirect()->guest(route('login'));

        if ($request->expectsJson()) {
            return response()->json(['error' => 'Unauthenticated.'], 401);
        }

        //dd($exception->guards());
        // $guard = array_get($exception->guards(), 0);
        $guard = Arr::get($exception->guards(),0);
        switch ($guard) {
            case 'admin':
                $login = 'admin.login';
                break;

            default:
                $login = 'login';
                break;
        }
        return redirect()->guest(route($login));
    }
}



15. add some code on middle/RedirectIfAuthenticated.php file


         public function handle($request, Closure $next, $guard = null)
            {
                // if (Auth::guard($guard)->check()) {
                //     return redirect(RouteServiceProvider::HOME);
                // }

        switch ($guard){
            case 'admin':
                if (Auth::guard($guard)->check()) {
                    return redirect()->route('admin.home');
                }
                break;

            default:
                if (Auth::guard($guard)->check()) {
                    return redirect()->route('home');
                }
                break;
        }

        return $next($request);
    }


 16. change some code in  namespace Illuminate\Foundation\Auth\AuthenticatesUsers  trait;
 


         public function logout(Request $request)
            {
                $this->guard()->logout();

          //  $request->session()->invalidate();
             return redirect('/');

            // $request->session()->regenerateToken();

            // if ($response = $this->loggedOut($request)) {
            //     return $response;
            // }

            // return $request->wantsJson()
            //     ? new Response('', 204)
            //     : redirect('/');
        }
   
