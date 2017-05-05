using System.Linq;
using Microsoft.AspNet.Identity;
using Microsoft.Owin.Security;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Principal;
using System.Web;
using System.Web.Mvc;
using System.Threading;

namespace CoockieAuth.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult Login()
        {
            if (HttpContext.GetOwinContext().Authentication.User.Identity.IsAuthenticated)
                return RedirectToAction("Home");
            return View();
        }

        [HttpPost]
        public ActionResult Login(Models.LoginModel models)
        {
            var claims = GetClaims(models);
            if (claims != null)
            {
                SignIn(claims);
                return RedirectToAction("Home");
            }
            return View();
        }

        private List<Claim> GetClaims(Models.LoginModel models)
        {
            var claims = new List<Claim>();
            claims.Add(new Claim(ClaimTypes.Email, models.Email));
            claims.Add(new Claim(ClaimTypes.Name, "Chandresh"));
            return claims;
        }

        private void SignIn(List<Claim> claims)
        {
            var claimsIdentity = new ClaimsIdentity(claims, DefaultAuthenticationTypes.ApplicationCookie);
            HttpContext.GetOwinContext().Authentication.SignIn(
                new AuthenticationProperties()
                {
                    IsPersistent = false
                }, claimsIdentity
            );
        }
        private void SetPrincipal(IPrincipal principal)
        {
            Thread.CurrentPrincipal = principal;
            if (System.Web.HttpContext.Current != null)
            {
                System.Web.HttpContext.Current.User = principal;
            }
        }

        [Authorize]
        public ActionResult Home()
        {
            var claims = HttpContext.GetOwinContext().Authentication.User.Claims;
            ViewBag.Email = claims.Where(x => x.Type == ClaimTypes.Email).FirstOrDefault().Value;
            return View();
        }
    }


}