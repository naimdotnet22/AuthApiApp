using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthApiApp.Models.DTO
{
    public class UserDTO
    {
        public UserDTO(string fullname,string email,string username, DateTime dateCreated)
        {
            FullName = fullname;
            Email = email;
            UserName = username;
            DateCreated = dateCreated;
        }
        public string FullName { get; set; }
        public string Email { get; set; }
        public string UserName { get; set; }
        public DateTime DateCreated { get; set; }
        public string Token { get; set; }
    }
}
