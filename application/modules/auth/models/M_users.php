<?php defined('BASEPATH') OR exit('No direct script access allowed');

class M_users extends CI_Model
{
    protected $user_table = 'users';

    public function store(array $data){
        $this->db->insert($this->user_table, $data);
        return $this->db->insert_id();
    }

    public function user_login($email, $password){
        $this->db->where('email', $email);
        $q = $this->db->get($this->user_table);

        if($q->num_rows()) {
            $user_pass = $q->row('password');
            if(md5($password) === $user_pass){
                return $q->row();
            }
            return FALSE;
        }else{
            return FALSE;
        }
    }
}