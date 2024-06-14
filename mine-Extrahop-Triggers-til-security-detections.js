// 
// checker i starten at det er CIFS , Men egentlig kun vigtig hvis "Events" IKKE er af typen CIFS_RESPONSE eller CIFS_REQUEST
// F.EKS hvis "Events" er af typen "FLOW_RECORD" er det vigtigt at der checkes om lag-7 er CIFS
if ( Flow.l7proto !== 'CIFS' ) 
{    
    return;
}


/*
if (( Flow.l7proto !== 'CIFS' ) && ( CIFS.method !== 'SMB2_NEGOTIATE' )) 
{    
    return;
}
*/

// var klient_buffer = Flow.client.payload, srv_buffer = Flow.server.payload;

var cifs_metode = CIFS.method;
if ( cifs_metode === 'SMB2_NEGOTIATE' )
{    
    debug(">>>>> Hvis cifs_metode er lig med \"SMB2_NEGOTIATE\" <<<<<");
    debug(cifs_metode);
    // skal rettes - debug(Flow.server.payload);
    if (Flow.l7proto.match("sec"))
    {
        debug(Flow.l7proto);
    }
    /*if (Flow.l7proto.search.prototype("sec")) 
    {
        debug("security");
    }
    */
    debug("Her vises SMB versions dialect: " + CIFS.dialect  + "SourceIP " + Flow.client.ipaddr + " accessed " + Flow.server.ipaddr);
}


//
{   
    debug(" Her printes hvilken lag-7 protokol: " + Flow.l7proto);
    

    // Hvis CIFS metoden >>equels<< med SMB2_NEGOTIATE
    if ( CIFS.method === 'SMB2_NEGOTIATE' )
    {
        debug("\n Her printes CIFS metoden: " + CIFS.method + "\n");
        debug(" Her printes \"CIFS request Version\": " + CIFS.reqVersion + "\n");
    }
    
    // Hvis CIFS metoden >>NOT equels<< med SMB2_NEGOTIATE
    if ( CIFS.method !== 'SMB2_NEGOTIATE' )
    {    
        debug("Her printes ikke SMB2 negotiate , kun alle andre metoder: " + CIFS.method + "\n");
    } 
    
}








// Events typen er SSL_OPEN

// 
//
var url_1 = ["api-eu.securitycenter.windows.com"];

if (url_1.indexOf(SSL.host) > -1 )
{
    return;
}  


if (SSL.host === null || SSL.host.endsWith("azure.com") || SSL.host.endsWith("microsoft.com") || SSL.host.match("advisor59648986473621243.blob.core.windows.net"))
{
    return;
}    

//PowerShell clients are identified by JA3 hashes
if(SSL.ja3Hash !== null)
    {
        //PowerShell clients are identified by JA3 hashes
        debug("Her ses JA3 hashen: " + SSL.ja3Hash + "\n");
        debug(SSL.host);
    
        commitDetection('Suspicious_Powershell_Activity', 
        {
            categories: ["sec.caution"],
            title: "Suspicious Powershell Activity",
            description: "Client IP: " + Flow.client.ipaddr + " accessed this Server IP: " + Flow.server.ipaddr,
            identityKey: getTimestamp().toString(),
            riskScore: 40, 
            participants:
            [
                { role: 'offender', object: Flow.server.device},
                { role: 'victim', object: Flow.client.device }
            ] 
        });
    } 
    // end   
   

//





// GitHack Access , Events typen er SSL_OPEN
//
if (SSL.host === null)
{
    return;
}    

if(SSL.host.match("githack"))
{
    debug(SSL.host);
    
    commitDetection('GitHack_access', 
    {
        categories: ["sec.caution"],
        title: "GitHack Access",
        description: "Client IP: " + Flow.client.ipaddr + " accessed this Server IP: " + Flow.server.ipaddr,
        identityKey: getTimestamp().toString(),
        riskScore: 30,    
        participants:
        [
            { role: 'offender', object: Flow.server.device},
            { role: 'victim', object: Flow.client.device }
        ]
        

    });
}
// end




// Pastebin or Githack Access , Events typen er SSL_OPEN
//
if (SSL.host === null)
{
    return;
}    

if(SSL.host.match("pastebin.com") || SSL.host.match("githack"))
{
    debug(SSL.host);
    
    commitDetection('pastebin_or_githack_access', 
    {
        categories: ['sec.action', "sec.command"],
        title: "Pastebin or Githack Access",
        description: "Client IP: " + Flow.client.ipaddr + " accessed this Server IP: " + Flow.server.ipaddr,
        identityKey: getTimestamp().toString(),
        riskScore: 50, 
        participants:
        [
            { role: 'offender', object: Flow.server.device},
            { role: 'victim', object: Flow.client.device }
        ]
        

    });
}
// end




