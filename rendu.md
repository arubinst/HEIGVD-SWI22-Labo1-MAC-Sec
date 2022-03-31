# Sécurité des réseaux sans fil

## Laboratoire 802.11 sécurité MAC

Auteurs: Godi Matthieu, Issolah Maude

Date: 31.03.2022



## Partie 1 - beacons, authenfication

### Deauthentication attack

**Questions**:

- Quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interprétation ?

  - Le code 7: Class 3 frame received from nonassociated STA.

  - La station a essayé d'envoyer des données avant d'être associée à l'AP.

  <img src="images\rendu\deauth-aircrack.png" style="border:1px solid grey;zoom:70%;" />

  

- A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interprétation ?

  Toutes les trames de désautentification étaient du même type.

  

- Quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

  Les codes qui impliquent un problème du côté de la STA, ou du réseau.

  La station reçoit une information de pourquoi elle a été déconnectée.

  - 1: Unspecified reason
  - 2: Previous authentication no longer valid
  - 4: Disassociated due to inactivity
  - 6: Class 2 frame received from nonauthenticated station
  - 7: Class 3 frame received from nonassociated station
  - 9: Station requesting (re)association is not authenticated with responding station

  

- Quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

  Les codes qui impliquent un problème du côté de l'AP, ce qui coupe la connexion et désauthentifie la station:

  - 3: station is leaving (or has left) IBSS or ESS
  - 5: Disassociated because AP is unable to handle all currently associated stations
  - 8: Disassociated because sending station is leaving (or has left) BSS

  

- Comment essayer de déauthentifier toutes les STA ?

  En envoyant un message de déasuthentification en broadcast.

  

- Quelle est la différence entre le code 3 et le code 8 de la liste ?

  Le code 3 est dû à la disparition de l'access point, tandis que le 8, est dû à un changement d'access point fait par l'os de la station.

  

- Expliquer l'effet de cette attaque sur la cible

  La connexion entre l'AP et la STA est coupée, et la STA doit se réauthentifier.
  
  

**Script:** deauthentication.py 

<img src="images\rendu\deauth-script-cmd.png" style="border:1px solid grey;zoom:80%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console</div>

Validation:

Dans Wireshark nous pouvons vérifier que nous envoyons bien un message de désauthentification de l'AP en broadcast, et que ce message a bien le code choisi par l'utilisateur (ici le 4).

<img src="images\rendu\deauth-script.png" style="border:1px solid grey;zoom:80%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Validation via Wireshark</div>





### Fake channel evil tween attack

Ce script liste les AP disponibles, sauf ceux qui n'ont pas de nom, car impossible à copier.

**Script:** fake-channel.py 

<img src="images\rendu\fake-cmd.png" style="border:1px solid grey;zoom:80%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console</div>



Validation:

Dans Wireshark nous pouvons vérifier que nous envoyons bien des beacons avec le même SSID que celui choisi par l'utilisateur, et sur le canal calculé par le script à une distance de 6 du canal d'origine. Ici le canal d'origine est le 11, et les beacons forgée sont envoyées sur le canal 5.

<img src="images\rendu\fake-WS.png" style="border:1px solid grey;zoom:80%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Validation via Wireshark</div>



Ci-dessous, nous pouvons observer les deux AP avec le même nom.

<img src="images\rendu\fake-phone2.jpeg" style="border:1px solid grey;zoom:40%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Validation via un mobile</div>



__Question__ : Expliquer l'effet de cette attaque sur la cible

Cette attaque trompe la cible, qui peut se connecter automatiquement au faux réseau, s'il n'y a pas de mot de passe demandé.



### SSID flood attack

**Script:** ssid-flood-attack.py

Si le script est lancé sans argument, il va créer le nombre de SSID demandé par l'utilisateur. 

Le pattern de nommage de ces SSID est: *abc-12345*. une fois créés, le script affiche la liste des SSIDs.

<img src="images\rendu\flood-cmd.png" style="border:1px solid grey;zoom:100%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console, sans argument</div>



<img src="images\rendu\flood-cmd-list.png" style="border:1px solid grey;zoom:100%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console, avec une liste de SSID en argument</div>

Vérification:

Nous voyons que nous envoyons bien des beacons avec les noms de la liste comme SSID, et ci-après avec les noms crées aléatoirement.

<img src="images\rendu\flood-WS.png" style="border:1px solid grey;zoom:100%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Paquets créés depuis la liste de noms</div>



<img src="images\rendu\flood-WS2.png" style="border:1px solid grey;zoom:100%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Paquets crées avec des nom aléatoires</div>



## Partie 2 - Probes

### Probe Request Evil Twin Attack

**Question** : comment ça se fait que ces trames puissent être lues par tout le monde ? Ne serait-il pas plus judicieux de les chiffrer ?

La station cherche un réseau, mais n'est pas authentifiée. Elle ne peut donc pas chiffrer les probe request qu'elle envoi, car elle ne va pas créer une connexion sécurisée avec tous les AP qu'elle rencontre. Il est normal que ces messages ne soient pas chiffrées.



**Question** : pourquoi les dispositifs iOS et Android récents ne peuvent-ils plus être tracés avec cette méthode ?

Car ils créent des adresses MAC aléatoires pour cacher la vrai.

 

**Script:** twin-attack.py

Ce script prend un SSID en argument et créer un faux AP s'il trouve des stations cherchant ce SSID.

<img src="images\rendu\twin-attack-cmd.png" style="border:1px solid grey;zoom:100%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console</div>

Vérification:

Nous pouvons constater que nous envoyons bien des beacons se faisant passer pour l'AP.

<img src="images\rendu\twin-attack-WS.png" style="border:1px solid grey;zoom:90%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Validation via Wireshark</div>



### Détection de clients et réseaux

**Script:** sta-searching-ap.py

Ce script va lister les stations cherchant un AP spécifique passé en argument.

<img src="images\rendu\sta-search-ap-cmd.png" style="border:1px solid grey;zoom:100%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console</div>

Vérification:

Nous voyons dans Wireshark que le packet *Probe Request* a bien été pris en compte, et que la bonne adresse mac est affichée par le script.

<img src="images\rendu\sta-search-ap-ws.png" style="border:1px solid grey;zoom:90%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Validation via Wireshark</div>



**Script:** association.py

Ce script liste les stations associée à un AP.

Pour ce faire il utilise des paquets qui sont échangés par des pairs associés: *block ack*.

<img src="images\rendu\asso-cmd.png" style="border:1px solid grey;zoom:90%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console</div>



Vérification:

Vérification de la première ligne affichée dans le terminal.

Nous pouvons observer que les deux adresses sont bien listée dans la bonne colonne (AP/STA).

<img src="images\rendu\asso-WS.png" style="border:1px solid grey;zoom:90%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Validation via Wireshark</div>



### Hidden SSID reveal 

Ce script trouve les SSID cachés en commençant par lister les beacons qui n'ont pas de SSID (chaîne vide).

Il stock les adresses mac de ces AP, puis écoute les *probe request/response* pour trouver une de ces adresses. Le SSID caché se trouve dans les paquets *probe*.

**Script:** hidden-ap.py

<img src="images\rendu\hidden-cmd.png" style="border:1px solid grey;zoom:100%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Script en console</div>



Vérification:

En filtrant sur l'adresse mac donnée en console, on peut vérifier que cet AP envoi bien des *beacon*s vide, mais une *probe response* avec un SSID, et que c'est celui affiché en console.

<img src="images\rendu\hidden-ws.png" style="border:1px solid grey;zoom:90%;" />

<div style="text-align: center;font-style: italic;font-size: 12px;">Validation via Wireshark</div>
