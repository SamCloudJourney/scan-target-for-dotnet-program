#:sdk Aspire.AppHost.Sdk@17.0.0
#:package Aspire.Hosting.MySql@17.0.0
#:property AspireUseCliBundle=true

using Aspire.Hosting;

var builder = DistributedApplication.CreateBuilder(args);
var firstPassword = builder.AddParameter("f076one", secret: true);
builder.AddMySql("f076mysqlone", password: firstPassword, port: 13307)
    .WithContainerName("f076-mysql-one")
    .WithPhpMyAdmin(c => c.WithContainerName("f076-phpmyadmin"));

if (Environment.GetEnvironmentVariable("F076_SINGLE") != "1")
{
    var secondPassword = builder.AddParameter("f076two", secret: true);
    builder.AddMySql("f076mysqltwo", password: secondPassword, port: 13308)
        .WithContainerName("f076-mysql-two");
}

builder.Build().Run();
