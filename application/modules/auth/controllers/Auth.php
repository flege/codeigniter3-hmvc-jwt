<?php defined('BASEPATH') OR exit('No direct script access allowed');

use Restserver\Libraries\REST_Controller;

require APPPATH . '/libraries/REST_Controller.php';
 
class Auth extends REST_Controller
{
    public function __construct(){
        parent::__construct();
        $this->load->model('m_users');
    }

    public function register_post(){
        header("Access-Control-Allow-Origin: *");

        # XSS Filtering (https://www.codeigniter.com/user_guide/libraries/security.html)
        $_POST = $this->security->xss_clean($_POST);
    
        $this->form_validation->set_rules('nama', 'Naama', 'trim|required|max_length[50]');
        $this->form_validation->set_rules('email', 'Email', 'trim|required|valid_email|max_length[50]|is_unique[users.email]',
            array('is_unique' => 'This %s already exists please enter another email address')
        );
        $this->form_validation->set_rules('no_hp', 'No HP', 'trim|required|numeric|max_length[15]|is_unique[users.no_hp]',
            array('is_unique' => 'This %s already exists please enter another phone number')
        );
        $this->form_validation->set_rules('password', 'Password', 'trim|required|max_length[80]');
        if ($this->form_validation->run() == FALSE){
            $message = array(
                'status' => false,
                'error' => $this->form_validation->error_array(),
                'message' => validation_errors()
            );
            $this->response($message, REST_Controller::HTTP_NOT_FOUND);
        }else{
            $insert_data = [
                'nama' => $this->input->post('nama', TRUE),
                'email' => $this->input->post('email', TRUE),
                'no_hp' => $this->input->post('no_hp', TRUE),
                'password' => hash('sha256',md5($this->input->post('no_hp', TRUE)).$this->input->post('password', TRUE)),
            ];
            $output = $this->m_users->store($insert_data);
            if (empty($output)){
                // Success
                $message = [
                    'status' => true,
                    'message' => "Registrasi berhasil"
                ];
                $this->response($message, REST_Controller::HTTP_OK);
            }else{
                // Error
                $message = [
                    'status' => FALSE,
                    'message' => "Registrasi gagal."
                ];
                $this->response($message, REST_Controller::HTTP_NOT_FOUND);
            }
        }
    }

    public function login_post(){
        header("Access-Control-Allow-Origin: *");

        # XSS Filtering (https://www.codeigniter.com/user_guide/libraries/security.html)
        $_POST = $this->security->xss_clean($_POST);
        
        $this->form_validation->set_rules('email', 'Email', 'trim|required');
        $this->form_validation->set_rules('password', 'Password', 'trim|required|max_length[100]');
        if($this->form_validation->run() == FALSE){
            $message = array(
                'status' => false,
                'error' => $this->form_validation->error_array(),
                'message' => validation_errors()
            );
            $this->response($message, REST_Controller::HTTP_NOT_FOUND);
        }else{
            $output = $this->m_users->user_login($this->input->post('email'), $this->input->post('password'));
            if (!empty($output) AND $output != FALSE){
                // Load Authorization Token Library
                $this->load->library('Authorization_Token');

                // Generate Token
                $token_data['id'] = $output->id;
                $token_data['nama'] = $output->nama;
                $token_data['email'] = $output->email;
                $token_data['time'] = time();
                $user_token = $this->authorization_token->generateToken($token_data);

                $return_data = [
                    'user_id' => $output->id,
                    'nama' => $output->nama,
                    'email' => $output->email,
                    'created_at' => $output->created_at,
                    'token' => $user_token,
                ];

                // Login Success
                $message = [
                    'status' => true,
                    'data' => $return_data,
                    'message' => "Login successfull"
                ];
                $this->response($message, REST_Controller::HTTP_OK);
            }else{
                // Login Error
                $message = [
                    'status' => FALSE,
                    'message' => "Invalid Email or Password"
                ];
                $this->response($message, REST_Controller::HTTP_NOT_FOUND);
            }
        }
    }
}
