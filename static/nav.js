document.addEventListener("DOMContentLoaded", function () {
    const token = localStorage.getItem("token");
    const authLink = document.getElementById("auth-link");
    const logoutButton = document.getElementById("logout-button");
    const createArticleLink = document.getElementById("create-article-link");
    const adminPanelLink = document.getElementById("admin-panel-link");
    const profileLink = document.getElementById("profile-link");

    function parseJwt(token) {
        try {
            return JSON.parse(atob(token.split('.')[1]));
        } catch (e) {
            return null;
        }
    }

    const userData = parseJwt(token);

    if (userData) {
        console.log("✅ User detected:", userData);
        if (authLink) authLink.style.display = "none";
        if (logoutButton) logoutButton.style.display = "inline-block";
        if (profileLink) profileLink.style.display = "inline-block";

        if (userData.role === "admin") {
            if (adminPanelLink) adminPanelLink.style.display = "inline-block";
            if (createArticleLink) createArticleLink.style.display = "inline-block";
        } else {
            if (createArticleLink) createArticleLink.style.display = "inline-block";
            if (adminPanelLink) adminPanelLink.style.display = "none";
        }
    } else {
        console.log("❌ No valid user found. Redirecting...");
        if (window.location.pathname !== "/register.html") {
            window.location.href = "/register.html";
        }
    }

    if (logoutButton) {
        logoutButton.addEventListener("click", function () {
            localStorage.removeItem("token");
            window.location.href = "/articles.html";
        });
    }
});
