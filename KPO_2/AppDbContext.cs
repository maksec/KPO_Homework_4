using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

public class user
{
    public int id { get; set; }
    public string username { get; set; }
    public string email { get; set; }
    public string password_hash { get; set; }
    public string role { get; set; }
    public DateTime created_at { get; set; }
    public DateTime updated_at { get; set; }
}

public class session
{
    public int id { get; set; }
    public int user_id { get; set; }
    public string session_token { get; set; }
    public DateTime expires_at { get; set; }
}
public class AppDbContext : DbContext
{
    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseNpgsql("Host=localhost;Port=5432;Database=kpo;Username=maxec;Password=1521");
        }
    }

    public DbSet<user> user { get; set; }
    public DbSet<session> session { get; set; }
}
