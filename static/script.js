document.getElementById("urlForm").addEventListener("submit", async (e) => {
    e.preventDefault();

    const urlInput = document.getElementById("urlInput").value;
    const resultDiv = document.getElementById("result");

    resultDiv.textContent = "";
    resultDiv.classList.remove("phishing", "legitimate");

    if (!urlInput) {
        alert("Please enter a URL.");
        return;
    }

    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ url: urlInput }),
        });

        if (!response.ok) {
            throw new Error("Network response was not ok.");
        }

        const data = await response.json();

        resultDiv.textContent = `Result: ${data.prediction}`;
        if (data.prediction === "Phishing") {
            resultDiv.classList.add("phishing");
        } else {
            resultDiv.classList.add("legitimate");
        }
    } catch (error) {
        console.error("Error:", error);
        resultDiv.textContent = "An error occurred. Please try again.";
    }
});