<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use App\Models\User;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Facades\View;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        View::composer('*', function ($view) {
            $userId = Session::get('loginId');
            $loggedInUser = null;
    
            // Check if the user is logged in
            if ($userId) {
                $loggedInUser = User::find($userId);
            }
    
            // Share the logged-in user data with all views
            $view->with('loggedInUser', $loggedInUser);
        });
    }
}
