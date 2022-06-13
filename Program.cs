using Microsoft.AspNetCore.Identity;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
#region ConfigureService
builder.Services.AddControllersWithViews().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.WriteIndented = true;
});

builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.CheckConsentNeeded = context => true;
    options.MinimumSameSitePolicy = SameSiteMode.None;
});

builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "X-CSRF-TOKEN-WEBAPPTrasporti";
    options.HeaderName = "X-CSRF-TOKEN-WEBAPPTrasporti";
    options.FormFieldName = "X-CSRF-TOKEN-WEBAPPTrasporti";
});

//TODO CONFIGURE EMAIL SENDER SERVICE

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(Configuration.GetConnectionString("DefaultConnection")));

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedPhoneNumber = true;
    options.Password.RequireDigit = true; ;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredLength = 8;
    options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._@+";
    options.Lockout.DefaultLockoutTimeSpan = System.TimeSpan.FromMinutes(5);
    options.Lockout.AllowedForNewUsers = true;
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.SignIn.RequireConfirmedAccount = true;
    options.SignIn.RequireConfirmedEmail = true;
    options.User.RequireUniqueEmail = true;
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.AddControllersWithViews();

builder.Services.AddAuthentication("MyWEBAPPTrasportiIdentity").AddCookie("MyWEBAPPTrasportiIdentity", option =>
{
    option.Cookie.Name = "MyWEBAPPTrasportiIdentity";
    option.Cookie.HttpOnly = true;
    option.ExpireTimeSpan = TimeSpan.FromDays(1);
    option.SlidingExpiration = true;
    option.LoginPath = "/login";
});

#region Claims Role Initialization

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("UserRole", policy => policy.RequireClaim(ClaimTypes.Role, "User"));
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("SeoRole", policy => policy.RequireClaim(ClaimTypes.Role, "Seo"));
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("LogisticRole", policy => policy.RequireClaim(ClaimTypes.Role, "Logistic"));
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("HRRole", policy => policy.RequireClaim(ClaimTypes.Role, "HR"));
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("DriverRole", policy => policy.RequireClaim(ClaimTypes.Role, "Driver"));
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("CustomerRole", policy => policy.RequireClaim(ClaimTypes.Role, "Customer"));
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminRole", policy => policy.RequireClaim(ClaimTypes.Role, "Admin"));
});

#endregion

builder.Services.AddControllersWithViews();
#endregion
var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseCookiePolicy();
app.UseAuthentication();
app.UseAuthorization();
app.UseRouting();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action=Index}/{id?}");

app.MapFallbackToFile("index.html"); ;

app.Run();