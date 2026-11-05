using OpensshUI.Services.Auth;

namespace OpensshUI.Tests;

public class UserSessionStateTests
{
    [Fact]
    public void InitialState_ShouldBeUnauthenticated()
    {
        var session = new UserSessionState();

        Assert.False(session.IsAuthenticated);
        Assert.Equal(string.Empty, session.CurrentUsername);
        Assert.Equal(string.Empty, session.DisplayName);
        Assert.False(session.IsAdmin);
        Assert.Null(session.LoginTime);
    }

    [Fact]
    public void SetUser_ShouldUpdatePropertiesAndTriggerOnChange()
    {
        var session = new UserSessionState();
        var eventFired = false;
        session.OnChange += () => eventFired = true;

        session.SetUser("testadmin", "Test Administrator", true);

        Assert.True(session.IsAuthenticated);
        Assert.Equal("testadmin", session.CurrentUsername);
        Assert.Equal("Test Administrator", session.DisplayName);
        Assert.True(session.IsAdmin);
        Assert.NotNull(session.LoginTime);
        Assert.True(eventFired);
    }

    [Fact]
    public void Logout_ShouldResetStateAndTriggerOnChange()
    {
        var session = new UserSessionState();
        session.SetUser("admin", "Admin User", true);

        var eventFired = false;
        session.OnChange += () => eventFired = true;

        session.Logout();

        Assert.False(session.IsAuthenticated);
        Assert.Equal(string.Empty, session.CurrentUsername);
        Assert.Equal(string.Empty, session.DisplayName);
        Assert.False(session.IsAdmin);
        Assert.Null(session.LoginTime);
        Assert.True(eventFired);
    }
}
