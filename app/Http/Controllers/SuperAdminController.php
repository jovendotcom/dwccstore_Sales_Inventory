<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use App\Models\User;
use Session;

class SuperAdminController extends Controller
{
    public function superadminlogin(){
        return view("auth.superadminlogin");
    }

    public function superadminregistration(){
        return view("auth.superadminregistration");
    }

    //superadmin registration
    public function register_superadmin(Request $request){
        $request->validate([
            'full_name'=>'required',
            'emp_id'=>'required|unique:users',
            'username'=>'required',
            'password'=>'required|min:5|max:12',
            'confirmpassword'=>'required|same:password',
        ]);

        $user = new User();
        $user->full_name = $request->full_name;
        $user->emp_id = $request->emp_id;
        $user->username = $request->username;
        $user->password = bcrypt($request->password);
        $user->user_role = 'SuperAdmin';
        $user->user_status = 'Active';
        $res = $user->save();

        if ($res){
            return back()->with('success', 'Account created sucessfully!');
        }
        else{
            return back()->with('fail', 'Something Wrong!');
        }
    }

    //superadmin login function
    public function login_superadmin(Request $request){
        // Validate input
        $request->validate([
            'username' => 'required',
            'password' => 'required|min:5|max:12',
        ]);

        // Check if the user exists
        $user = User::where('username', $request->username)->first();

        if ($user) {
            // Check if the password matches
            if (Hash::check($request->password, $user->password)) {
                // Store user ID in session
                $request->session()->put('loginId', $user->id);

                // Redirect to the dashboard after login
                return view('auth.superadmin_dashboard');
            } else {
                return back()->with('fail', 'Incorrect Password!');
            }
        } else {
            return back()->with('fail', 'Username is not registered!');
        }
    }

    //superadmin dashboard function 
    public function superadmin_dashboard(){
        // Retrieve the logged-in user's ID from the session
        $userId = Session::get('loginId');

        // Check if the user is logged in
        if ($userId) {
            $loggedInUser = User::find($userId); // Fetch user by ID
        } else {
            return redirect('login_superadmin')->with('fail', 'You must be logged in.');
        }

        // Pass the logged-in user's data to the view
        return view('auth.superadmin_dashboard', compact('loggedInUser'));
    }

    //superadmin user_management function 
    public function user_management(){
        return view("auth.user_management");
    }

    public function logout(Request $request)
    {
        // Destroy the user session
        $request->session()->forget('loginId');
        $request->session()->flush();

        // Redirect to login page
        return redirect('/superadminlogin')->with('success', 'You have been logged out successfully.');
    }
}
