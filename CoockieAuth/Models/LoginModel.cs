﻿using System.ComponentModel.DataAnnotations;

namespace CoockieAuth.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Email is required!")]
        [DataType(DataType.EmailAddress)]
        public string Email { get; set; }

        [Required(ErrorMessage = "Password is required!")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}