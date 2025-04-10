async function analyzeURL() {
    const urlInput = document.getElementById('urlInput').value;
    const resultsDiv = document.getElementById('results');
    const securityScoreDiv = document.getElementById('securityScore');
    const securityFeaturesDiv = document.getElementById('securityFeatures');
    const websiteInfoDiv = document.getElementById('websiteInfo');

    if (!urlInput) {
        alert('Please enter a URL to analyze');
        return;
    }

    try {
        // Show loading state
        resultsDiv.style.display = 'block';
        securityScoreDiv.innerHTML = '<div class="text-center"><div class="spinner-border" role="status"></div><p>Analyzing URL...</p></div>';
        securityFeaturesDiv.innerHTML = '';
        websiteInfoDiv.innerHTML = '';

        // Analyze URL
        const analyzeResponse = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: urlInput }),
        });

        const analyzeData = await analyzeResponse.json();

        // Get website info
        const infoResponse = await fetch('/website-info', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: urlInput }),
        });

        const infoData = await infoResponse.json();

        // Update UI with results
        const confidence = (analyzeData.confidence * 100).toFixed(2);
        const statusClass = analyzeData.is_phishing ? 'danger' : 'success';
        const statusIcon = analyzeData.is_phishing ? 'fa-exclamation-triangle' : 'fa-check-circle';
        
        securityScoreDiv.innerHTML = `
            <div class="alert alert-${statusClass}">
                <h4><i class="fas ${statusIcon}"></i> Security Analysis Result</h4>
                <p>This URL is ${analyzeData.is_phishing ? 'likely a PHISHING site' : 'likely LEGITIMATE'}</p>
                <p>Confidence: ${confidence}%</p>
            </div>
        `;

        // Security Features
        const securityFeatures = analyzeData.security_info;
        let featuresHtml = '<ul class="list-group">';
        
        if (securityFeatures.ssl_cert !== undefined) {
            featuresHtml += `
                <li class="list-group-item">
                    <i class="fas ${securityFeatures.ssl_cert ? 'fa-lock text-success' : 'fa-lock-open text-danger'}"></i>
                    SSL Certificate: ${securityFeatures.ssl_cert ? 'Valid' : 'Invalid'}
                </li>`;
        }
        
        if (securityFeatures.domain_age !== undefined) {
            featuresHtml += `
                <li class="list-group-item">
                    <i class="fas fa-calendar"></i>
                    Domain Age: ${securityFeatures.domain_age ? securityFeatures.domain_age + ' days' : 'Unknown'}
                </li>`;
        }

        if (securityFeatures.security_headers) {
            Object.entries(securityFeatures.security_headers).forEach(([header, present]) => {
                featuresHtml += `
                    <li class="list-group-item">
                        <i class="fas ${present ? 'fa-check text-success' : 'fa-times text-danger'}"></i>
                        ${header}: ${present ? 'Present' : 'Missing'}
                    </li>`;
            });
        }

        featuresHtml += '</ul>';
        securityFeaturesDiv.innerHTML = featuresHtml;

        // Website Information
        if (!infoData.error) {
            websiteInfoDiv.innerHTML = `
                <div class="card">
                    <div class="card-body">
                        <h5 class="card-title">${infoData.title}</h5>
                        <p class="card-text">${infoData.meta_description}</p>
                        <p><strong>Status Code:</strong> ${infoData.status_code}</p>
                    </div>
                </div>
            `;
        } else {
            websiteInfoDiv.innerHTML = `
                <div class="alert alert-warning">
                    <i class="fas fa-exclamation-circle"></i>
                    Could not fetch website information
                </div>
            `;
        }

    } catch (error) {
        console.error('Error:', error);
        resultsDiv.innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle"></i>
                An error occurred while analyzing the URL. Please try again.
            </div>
        `;
    }
}

// Add a function to fetch and display website information
function getWebsiteInfo(url) {
    // Show loading spinner
    $('#loading-spinner').removeClass('d-none');
    
    // Clear any previous alerts
    $('#alert-section').empty();
    
    // Validate URL
    if (!url) {
        showAlert('Please enter a URL to analyze', 'danger');
        $('#loading-spinner').addClass('d-none');
        return;
    }
    
    // Show that we're analyzing
    showAlert('Analyzing website information...', 'info');
    
    // Make the AJAX request to get website info
    $.ajax({
        url: '/website-info',
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({url: url}),
        success: function(response) {
            // Hide loading spinner
            $('#loading-spinner').addClass('d-none');
            
            // Clear info alert
            $('#alert-section').empty();
            
            if (response.error) {
                showAlert(response.error, 'danger');
                return;
            }
            
            // Show the website info section
            $('#website-info-section').removeClass('d-none');
            
            // Display Basic Information Tab
            updateBasicInformation(response);
            
            // Display Security Information Tab
            updateSecurityInformation(response);
            
            // Display WHOIS & DNS Tab
            updateWhoisAndDns(response);
            
            // Display SEO Analysis Tab
            updateSeoAnalysis(response);
            
            // Display Links Tab
            updateLinksInformation(response);
            
            // Display Tech Stack Tab
            updateTechStackInformation(response);
            
            // Scroll to the results
            $('html, body').animate({
                scrollTop: $('#website-info-section').offset().top - 100
            }, 1000);
        },
        error: function() {
            // Hide loading spinner
            $('#loading-spinner').addClass('d-none');
            
            // Show error message
            showAlert('Error analyzing website. Please try again.', 'danger');
        }
    });
}

function updateBasicInformation(response) {
    // Basic Domain Information
    $('#domain-info').text(response.domain || 'N/A');
    $('#title-info').text(response.title || 'N/A');
    $('#description-info').text(response.description || 'N/A');
    $('#keywords-info').text(response.keywords || 'N/A');
    $('#domain-age-info').text(response.domain_age || 'N/A');
    
    // Content Overview
    $('#content-size-info').text(response.content_size || 'N/A');
    
    // Heading Structure
    let headingStructure = '';
    if (response.h1_count !== undefined || response.h2_count !== undefined) {
        headingStructure = `H1: ${response.h1_count || 0}, H2: ${response.h2_count || 0}`;
        if (response.h3_count !== undefined) {
            headingStructure += `, H3: ${response.h3_count || 0}`;
        }
    } else {
        headingStructure = 'N/A';
    }
    $('#heading-structure-info').text(headingStructure);
    
    // Images
    let imagesInfo = 'N/A';
    if (response.image_count !== undefined) {
        imagesInfo = `${response.image_count || 0} images`;
        if (response.images_missing_alt !== undefined) {
            imagesInfo += ` (${response.images_missing_alt || 0} missing alt)`;
        }
    }
    $('#images-info').text(imagesInfo);
    
    // Total Links & Canonical URL
    $('#total-links-info').text(response.total_links || 'N/A');
    $('#canonical-url-info').text(response.canonical_url || 'N/A');
}

function updateSecurityInformation(response) {
    // SSL Status
    let sslInfo = response.ssl || 'Not Available';
    if (sslInfo === true || sslInfo === 'true') {
        $('#ssl-info').html('<span class="text-success">Secure (HTTPS)</span>');
    } else if (sslInfo === false || sslInfo === 'false') {
        $('#ssl-info').html('<span class="text-danger">Not Secure (HTTP)</span>');
    } else {
        $('#ssl-info').text(sslInfo);
    }
    
    // Trusted Domain
    let trustedDomainInfo = response.trusted_domain || false;
    if (trustedDomainInfo === true || trustedDomainInfo === 'true') {
        $('#trusted-domain-info').html('<span class="text-success">Yes</span>');
    } else {
        $('#trusted-domain-info').html('<span class="text-warning">No</span>');
    }
    
    // Security Summary & Score
    let suspiciousScore = response.suspicious_score || 0;
    $('#suspicious-score-info').text(suspiciousScore + '/10');
    
    let securitySummary = '';
    if (suspiciousScore >= 7) {
        securitySummary = '<div class="alert alert-danger">High risk - Multiple security issues detected</div>';
    } else if (suspiciousScore >= 4) {
        securitySummary = '<div class="alert alert-warning">Medium risk - Some security concerns</div>';
    } else {
        securitySummary = '<div class="alert alert-success">Low risk - Appears to be secure</div>';
    }
    $('#security-summary').html(securitySummary);
    
    // Security Headers
    let securityHeadersTable = '';
    if (response.security_headers && Object.keys(response.security_headers).length > 0) {
        for (const [header, value] of Object.entries(response.security_headers)) {
            let headerStatus = value ? 
                '<span class="text-success">✓ Present</span>' : 
                '<span class="text-danger">✗ Missing</span>';
            securityHeadersTable += `<tr><th>${header}</th><td>${headerStatus}</td></tr>`;
        }
    } else {
        securityHeadersTable = '<tr><td colspan="2">No security headers detected</td></tr>';
    }
    $('#security-headers-table').html(securityHeadersTable);
    
    // Security Issues
    let securityIssuesList = '';
    if (response.security_issues && response.security_issues.length > 0) {
        response.security_issues.forEach(issue => {
            securityIssuesList += `<li class="list-group-item list-group-item-danger">${issue}</li>`;
        });
    } else {
        securityIssuesList = '<li class="list-group-item list-group-item-success">No critical security issues detected</li>';
    }
    $('#security-issues-list').html(securityIssuesList);
    
    // Redirect Chain
    if (response.redirect_chain && response.redirect_chain.length > 0) {
        let redirectHtml = '<ol class="list-group list-group-numbered">';
        response.redirect_chain.forEach(url => {
            redirectHtml += `<li class="list-group-item">${url}</li>`;
        });
        redirectHtml += '</ol>';
        $('#redirect-chain-container').html(redirectHtml);
    }
}

function updateWhoisAndDns(response) {
    // WHOIS Information
    $('#whois-registrar').text(response.whois_registrar || 'N/A');
    $('#whois-creation').text(response.whois_creation_date || 'N/A');
    $('#whois-expiration').text(response.whois_expiration_date || 'N/A');
    $('#whois-updated').text(response.whois_updated_date || 'N/A');
    
    // Nameservers
    let nameservers = 'N/A';
    if (response.whois_nameservers && response.whois_nameservers.length > 0) {
        nameservers = response.whois_nameservers.join('<br>');
    }
    $('#whois-nameservers').html(nameservers);
    
    // Status
    let status = 'N/A';
    if (response.whois_status && response.whois_status.length > 0) {
        status = response.whois_status.join('<br>');
    }
    $('#whois-status').html(status);
    
    // DNS Records
    function renderDnsRecords(recordType, records) {
        if (!records || records.length === 0) {
            return '<p>No records found</p>';
        }
        
        let html = '<ul class="list-group">';
        records.forEach(record => {
            html += `<li class="list-group-item">${record}</li>`;
        });
        html += '</ul>';
        return html;
    }
    
    $('#dns-a-records').html(renderDnsRecords('A', response.dns_a));
    $('#dns-aaaa-records').html(renderDnsRecords('AAAA', response.dns_aaaa));
    $('#dns-mx-records').html(renderDnsRecords('MX', response.dns_mx));
    $('#dns-ns-records').html(renderDnsRecords('NS', response.dns_ns));
    $('#dns-txt-records').html(renderDnsRecords('TXT', response.dns_txt));
}

function updateSeoAnalysis(response) {
    // SEO Overview
    $('#title-length-info').text(response.title_length || 'N/A');
    
    // Meta Description & Keywords
    let metaDescription = response.meta_description || 'Missing';
    let metaDescriptionClass = metaDescription === 'Missing' ? 'text-danger' : 'text-success';
    $('#meta-description-info').html(`<span class="${metaDescriptionClass}">${metaDescription}</span>`);
    
    let metaKeywords = response.meta_keywords || 'Missing';
    let metaKeywordsClass = metaKeywords === 'Missing' ? 'text-warning' : 'text-success';
    $('#meta-keywords-info').html(`<span class="${metaKeywordsClass}">${metaKeywords}</span>`);
    
    // Heading Structure for SEO
    let headingStructureSeo = '';
    if (response.h1_count !== undefined) {
        if (response.h1_count === 0) {
            headingStructureSeo = '<span class="text-danger">Missing H1 tag</span>';
        } else if (response.h1_count > 1) {
            headingStructureSeo = `<span class="text-warning">Multiple H1 tags (${response.h1_count})</span>`;
        } else {
            headingStructureSeo = '<span class="text-success">Proper H1 usage</span>';
        }
        
        if (response.h2_count !== undefined) {
            headingStructureSeo += `, H2: ${response.h2_count}`;
        }
    } else {
        headingStructureSeo = 'N/A';
    }
    $('#heading-structure-seo-info').html(headingStructureSeo);
    
    // Images Alt Text
    let imagesAlt = 'N/A';
    if (response.image_count !== undefined && response.images_missing_alt !== undefined) {
        if (response.image_count === 0) {
            imagesAlt = 'No images found';
        } else if (response.images_missing_alt === 0) {
            imagesAlt = `<span class="text-success">All ${response.image_count} images have alt text</span>`;
        } else {
            imagesAlt = `<span class="text-warning">${response.images_missing_alt} of ${response.image_count} images missing alt text</span>`;
        }
    }
    $('#images-alt-info').html(imagesAlt);
    
    // Canonical URL for SEO
    let canonicalUrl = response.canonical_url || 'Missing';
    let canonicalClass = canonicalUrl === 'Missing' ? 'text-warning' : 'text-success';
    $('#canonical-url-seo-info').html(`<span class="${canonicalClass}">${canonicalUrl}</span>`);
    
    // SEO Score
    let seoScore = response.seo_score || 0;
    $('#seo-score-bar').css('width', `${seoScore}%`).attr('aria-valuenow', seoScore).text(`${seoScore}%`);
    
    // Color the progress bar
    if (seoScore >= 70) {
        $('#seo-score-bar').removeClass('bg-danger bg-warning').addClass('bg-success');
    } else if (seoScore >= 40) {
        $('#seo-score-bar').removeClass('bg-danger bg-success').addClass('bg-warning');
    } else {
        $('#seo-score-bar').removeClass('bg-warning bg-success').addClass('bg-danger');
    }
    
    // SEO Recommendations
    let seoRecommendationsList = '';
    if (response.seo_recommendations && response.seo_recommendations.length > 0) {
        response.seo_recommendations.forEach(recommendation => {
            seoRecommendationsList += `<li class="list-group-item">${recommendation}</li>`;
        });
    } else {
        seoRecommendationsList = '<li class="list-group-item">No recommendations available</li>';
    }
    $('#seo-recommendations').html(seoRecommendationsList);
    
    // All Meta Tags
    let metaTags = 'No meta tags found';
    if (response.all_meta_tags && response.all_meta_tags.length > 0) {
        metaTags = '<div class="table-responsive"><table class="table table-bordered table-sm">';
        metaTags += '<thead><tr><th>Name/Property</th><th>Content</th></tr></thead><tbody>';
        
        response.all_meta_tags.forEach(meta => {
            metaTags += `<tr><td>${meta.name}</td><td>${meta.content}</td></tr>`;
        });
        
        metaTags += '</tbody></table></div>';
    }
    $('#meta-tags-info').html(metaTags);
}

function updateLinksInformation(response) {
    // Link Summary
    $('#internal-links-info').text(response.internal_links || '0');
    $('#external-links-info').text(response.external_links || '0');
    $('#total-links-summary').text(response.total_links || '0');
    
    // Suspicious Links
    let suspiciousLinks = response.suspicious_links || 0;
    if (suspiciousLinks > 0) {
        $('#suspicious-links-info').html(`<span class="text-danger">${suspiciousLinks} suspicious links</span>`);
    } else {
        $('#suspicious-links-info').html('<span class="text-success">None detected</span>');
    }
    
    // External Domains
    let externalDomains = 'No external domains found';
    if (response.external_domains && response.external_domains.length > 0) {
        externalDomains = '<ul class="list-group">';
        response.external_domains.forEach(domain => {
            let domainClass = domain.suspicious ? 'list-group-item-warning' : 'list-group-item-light';
            externalDomains += `<li class="list-group-item ${domainClass}">${domain.domain} (${domain.count} links)</li>`;
        });
        externalDomains += '</ul>';
    }
    $('#external-domains-container').html(externalDomains);
}

function updateTechStackInformation(response) {
    // Server Information
    $('#server-info').text(response.server || 'Unknown');
    $('#powered-by-info').text(response.powered_by || 'N/A');
    $('#content-type-info').text(response.content_type || 'N/A');
    
    // Status Code
    let statusCode = response.status_code || 'N/A';
    let statusClass = '';
    
    if (statusCode >= 200 && statusCode < 300) {
        statusClass = 'text-success';
    } else if (statusCode >= 300 && statusCode < 400) {
        statusClass = 'text-warning';
    } else {
        statusClass = 'text-danger';
    }
    
    $('#status-code-info').html(`<span class="${statusClass}">${statusCode}</span>`);
    
    // Technologies
    let technologies = 'Technology detection is limited in this version';
    if (response.technologies && response.technologies.length > 0) {
        technologies = '<div class="d-flex flex-wrap gap-2">';
        response.technologies.forEach(tech => {
            technologies += `<span class="badge bg-primary">${tech}</span>`;
        });
        technologies += '</div>';
    }
    $('#technologies-container').html(technologies);
}

// Add a function to show an alert message
function showAlert(message, type) {
    const alertContainer = document.getElementById('alert-container');
    if (!alertContainer) return;
    
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    alertContainer.innerHTML = '';
    alertContainer.appendChild(alertDiv);
}

// Add website info button to the URL form
document.addEventListener('DOMContentLoaded', function() {
    const urlForm = document.getElementById('url-form');
    
    // Add info button next to the submit button
    if (urlForm) {
        const submitButton = urlForm.querySelector('button[type="submit"]');
        if (submitButton) {
            const infoButton = document.createElement('button');
            infoButton.type = 'button';
            infoButton.className = 'btn btn-info ml-2';
            infoButton.textContent = 'Website Info';
            
            // Insert the info button after the submit button
            submitButton.parentNode.insertBefore(infoButton, submitButton.nextSibling);
            
            // Add event listener to the info button
            infoButton.addEventListener('click', function() {
                const urlInput = document.getElementById('url-input');
                if (urlInput && urlInput.value) {
                    getWebsiteInfo(urlInput.value);
                } else {
                    showAlert('Please enter a URL first', 'warning');
                }
            });
        }
    }
    
    // Add alert container if it doesn't exist
    if (!document.getElementById('alert-container')) {
        const container = document.querySelector('.container');
        if (container) {
            const alertContainer = document.createElement('div');
            alertContainer.id = 'alert-container';
            container.insertBefore(alertContainer, container.firstChild);
        }
    }
});