<?php

namespace App\Exceptions;

use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Throwable;
use Illuminate\Support\Arr;
use Exception;
//use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
use Request;
use Response;
use Illuminate\Auth\AuthenticationException;

class Handler extends ExceptionHandler
{
    /**
     * A list of the exception types that are not reported.
     *
     * @var array
     */
    protected $dontReport = [
        //
    ];

    /**
     * A list of the inputs that are never flashed for validation exceptions.
     *
     * @var array
     */
    protected $dontFlash = [
        'password',
        'password_confirmation',
    ];

    /**
     * Report or log an exception.
     *
     * @param  \Throwable  $exception
     * @return void
     *
     * @throws \Exception
     */
    public function report(Throwable $exception)
    {
        parent::report($exception);
    }

    /**
     * Render an exception into an HTTP response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Throwable  $exception
     * @return \Symfony\Component\HttpFoundation\Response
     *
     * @throws \Throwable
     */
    public function render($request, Throwable $exception)
    {
        return parent::render($request, $exception);
    }

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
