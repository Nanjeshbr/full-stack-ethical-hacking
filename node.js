 document.getElementById("date").innerText = new Date().toLocaleString();

    const vulnerabilities = [
      {
        name: "SQL Injection",
        desc: "Login form allows unsafe database queries.",
        severity: "High"
      },
      {
        name: "Cross-Site Scripting (XSS)",
        desc: "Input fields accept malicious scripts.",
        severity: "High"
      },
      {
        name: "Weak Password Policy",
        desc: "Users can set very weak passwords.",
        severity: "Medium"
      },
      {
        name: "Insecure File Upload",
        desc: "File upload page accepts dangerous file types.",
        severity: "High"
      },
      {
        name: "Missing HTTPS",
        desc: "Some pages are still using HTTP.",
        severity: "Medium"
      },
      {
        name: "Information Disclosure",
        desc: "Server error pages reveal sensitive information.",
        severity: "Low"
      }
    ];

    const table = document.getElementById("vulnTable");

    vulnerabilities.forEach(v => {
      const row = document.createElement("tr");

      let color = "low";
      if (v.severity === "High") color = "high";
      else if (v.severity === "Medium") color = "medium";

      row.innerHTML = `
        <td>${v.name}</td>
        <td>${v.desc}</td>
        <td><span class="status ${color}">${v.severity}</span></td>
      `;

      table.appendChild(row);
    });

    // Dynamic security score calculation
    const high = 5;
    const medium = 7;
    const low = 6;

    const totalPenalty = high * 10 + medium * 5 + low * 2;
    const score = Math.max(0, 100 - totalPenalty / 2);

    document.getElementById("securityScore").innerText = score + "%";