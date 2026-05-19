(function () {
    const savedCreds = localStorage.getItem("auth_credentials");
    if (!savedCreds) {
        window.location.replace("/login");
        return;
    }

    const originalFetch = window.fetch.bind(window);
    window.fetch = function (url, options = {}) {
        const headers = new Headers(options.headers || {});
        headers.set("Authorization", `Basic ${savedCreds}`);

        return originalFetch(url, { ...options, headers }).then((response) => {
            if (response.status === 401) {
                localStorage.removeItem("auth_credentials");
                window.location.replace("/login");
                throw new Error("Unauthorized");
            }
            return response;
        });
    };
})();

