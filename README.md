# Sécurité des réseaux sans fil

## Laboratoire 802.11 sécurité MAC

__A faire en équipes de deux personnes__


1. [Deauthentication attack](#1-deauthentication-attack)
2. [Fake channel evil tween attack](#2-fake-channel-evil-tween-attack)
3. [SSID Flood attack](#3-ssid-flood-attack)
4. [Probe Request Evil Twin Attack](#4-probe-request-evil-twin-attack)
5. [Détection de clients et réseaux](#5-d%c3%a9tection-de-clients-et-r%c3%a9seaux)
6. [Hidden SSID reveal](#6-hidden-ssid-reveal)
7. [Livrables](#livrables)
8. [Échéance](#%c3%89ch%c3%a9ance)



### Pour cette partie pratique, vous devez être capable de :

*	Détecter si un certain client WiFi se trouve à proximité
*	Obtenir une liste des SSIDs annoncés par les clients WiFi présents

Vous allez devoir faire des recherches sur internet pour apprendre à utiliser Scapy et la suite aircrack pour vos manipulations. __Il est fortement conseillé d'employer une distribution Kali__ (on ne pourra pas assurer le support avec d'autres distributions). __Si vous utilisez une VM, il vous faudra une interface WiFi usb, disponible sur demande__.

Des routers sans-fils sont aussi disponibles sur demande si vous en avez besoin (peut être utile pour l'exercices challenge 6).

__ATTENTION :__ Pour vos manipulations, il pourrait être important de bien fixer le canal lors de vos captures et/ou vos injections (à vous de déterminer si ceci est nécessaire pour les manipulations suivantes ou pas). Une méthode pour fixer le canal a déjà été proposée dans un laboratoire précédent.

## Quelques pistes utiles avant de commencer :

- Si vous devez capturer et injecter du trafic, il faudra configurer votre interface 802.11 en mode monitor.
- Python a un mode interactif très utile pour le développement. Il suffit de l'invoquer avec la commande ```python```. Ensuite, vous pouvez importer Scapy ou tout autre module nécessaire. En fait, vous pouvez même exécuter tout le script fourni en mode interactif !
- Scapy fonctionne aussi en mode interactif en invoquant la commande ```scapy```.  
- Dans le mode interactif, « nom de variable + <enter> » vous retourne le contenu de la variable.
- Pour visualiser en détail une trame avec Scapy en mode interactif, on utilise la fonction ```show()```. Par exemple, si vous chargez votre trame dans une variable nommée ```beacon```, vous pouvez visualiser tous ces champs et ses valeurs avec la commande ```beacon.show()```. Utilisez cette commande pour connaître les champs disponibles et les formats de chaque champ.
- Vous pouvez normalement désactiver la randomisation d'adresses MAC de vos dispositifs. Cela peut être utile pour tester le bon fonctionnement de certains de vos scripts. [Ce lien](https://www.howtogeek.com/722653/how-to-disable-random-wi-fi-mac-address-on-android/) vous propose une manière de le faire pour iOS et Android. 

## Partie 1 - beacons, authenfication

### 1. Deauthentication attack

Une STA ou un AP peuvent envoyer une trame de déauthentification pour mettre fin à une connexion.

Les trames de déauthentification sont des trames de management, donc de type 0, avec un sous-type 12 (0x0c). Voici le format de la trame de déauthentification :

![Trame de déauthentification](images/deauth.png)

Le corps de la trame (Frame body) contient, entre autres, un champ de deux octets appelé "Reason Code". Le but de ce champ est d'informer la raison de la déauthentification. Voici toutes les valeurs possibles pour le Reason Code :

| Code | Explication 802.11                                                                                                                                     |
|------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0    | Reserved                                                                                                                                              |
| 1    | Unspecified reason                                                                                                                                    |
| 2    | Previous authentication no longer valid                                                                                                               |
| 3    | station is leaving (or has left) IBSS or ESS                                                                                                          |
| 4    | Disassociated due to inactivity                                                                                                                       |
| 5    | Disassociated because AP is unable to handle all currently associated stations                                                                        |
| 6    | Class 2 frame received from nonauthenticated station                                                                                                  |
| 7    | Class 3 frame received from nonassociated station                                                                                                     |
| 8    | Disassociated because sending station is leaving (or has left) BSS                                                                                    |
| 9    | Station requesting (re)association is not authenticated with responding station                                                                       |
| 10   | Disassociated because the information in the Power Capability element is unacceptable                                                                 |
| 11   | Disassociated because the information in the Supported Channels element is unacceptable                                                               |
| 12   | Reserved                                                                                                                                              |
| 13   | Invalid information element, i.e., an information element defined in this standard for which the content does not meet the specifications in Clause 7 |
| 14   | Message integrity code (MIC) failure                                                                                                                                              |
| 15   | 4-Way Handshake timeout                                                                                                                                              |
| 16   | Group Key Handshake timeout                                                                                                                                              |
| 17   | Information element in 4-Way Handshake different from (Re)Association Request/Probe Response/Beacon frame                                                                                                                                              |
| 18   | Invalid group cipher                                                                                                                                              |
| 19   | Invalid pairwise cipher                                                                                                                                              |
| 20   | Invalid AKMP                                                                                                                                              |
| 21   | Unsupported RSN information element version                                                                                                                                              |
| 22   | Invalid RSN information element capabilities                                                                                                                                              |
| 23   | IEEE 802.1X authentication failed                                                                                                                                              |
| 24   | Cipher suite rejected because of the security policy                                                                                                                                              |
| 25-31 | Reserved                                                                                                                                              |
| 32 | Disassociated for unspecified, QoS-related reason                                                                                                                                              |
| 33 | Disassociated because QAP lacks sufficient bandwidth for this QSTA                                                                                                                                              |
| 34 | Disassociated because excessive number of frames need to be acknowledged, but are not acknowledged due to AP transmissions and/or poor channel conditions                                                                                                                                              |
| 35 | Disassociated because QSTA is transmitting outside the limits of its TXOPs                                                                                                                                              |
| 36 | Requested from peer QSTA as the QSTA is leaving the QBSS (or resetting)                                                                                                                                              |
| 37 | Requested from peer QSTA as it does not want to use the mechanism                                                                                                                                              |
| 38 | Requested from peer QSTA as the QSTA received frames using the mechanism for which a setup is required                                                                                                                                              |
| 39 | Requested from peer QSTA due to timeout                                                                                                                                              |
| 40 | Peer QSTA does not support the requested cipher suite                                                                                                                                              |
| 46-65535 | Reserved                                                                                                                                              |

a) Utiliser la fonction de déauthentification de la suite aircrack, capturer les échanges et identifier le Reason code et son interpretation.

__Question__ : quel code est utilisé par aircrack pour déauthentifier un client 802.11. Quelle est son interpretation ?

![image-20220310161439054](figures/image-20220310161439054.png)

On voit donc qu'il s'agit du code 7. Cela indique que le client a tenté de transférer des données avant son association.



__Question__ : A l'aide d'un filtre d'affichage, essayer de trouver d'autres trames de déauthentification dans votre capture. Avez-vous en trouvé d'autres ? Si oui, quel code contient-elle et quelle est son interpretation ?

Oui nous en avons trouvé une autre avec un autre Reason Code :

![image-20220310161834402](figures/image-20220310161834402.png)

Ici, il s'agit du code 2. Cela indique que le client s'est associé mais n'est pas autorisé.



b) Développer un script en Python/Scapy capable de générer et envoyer des trames de déauthentification. Le script donne le choix entre des Reason codes différents (liste ci-après) et doit pouvoir déduire si le message doit être envoyé à la STA ou à l'AP :

* 1 - Unspecified
* 4 - Disassociated due to inactivity
* 5 - Disassociated because AP is unable to handle all currently associated stations
* 8 - Deauthenticated because sending STA is leaving BSS

__Question__ : quels codes/raisons justifient l'envoie de la trame à la STA cible et pourquoi ?

Ce sont les codes 4 et 5 qui justifient l'envoi de la trame à la STA cible. En effet l'AP peut envoyer une trame de désauthentification avec le code 4 à la STA cible en raison de son inactivité sur le réseau. 

Pour ce qui est du code 5, si l'AP n'est pas capable de traiter toutes les STAs actuellement associées, il peut envoyer ce code-là pour désauthentifier la STA cible.

Cependant, le code 1 pourrait également être envoyé par l'AP à la STA cible étant donné que la raison n'est pas spécifiée. Pour des raisons de simplicité du script, le code 1 est toujours envoyé par la STA vers l'AP cible.



__Question__ : quels codes/raisons justifient l'envoie de la trame à l'AP et pourquoi ?

C'est le code 8 qui justifie l'envoi de la trame à l'AP cible. En effet, c'est à la STA de dire à l'AP qu'elle quitte le BSS (Basic Service Set).

Comme pour la question précédente, le code 1 pourrait être envoyé autant par la STA que par l'AP. Ici, nous avons défini que c'était la STA qui envoyait ce code à l'AP cible dans le script.



__Question__ : Comment essayer de déauthentifier toutes les STA ?

Il suffit de mettre l'adresse MAC `FF:FF:FF:FF:FF:FF` comme adresse cible afin de désauthentifier toutes les STAs connectées à l'AP choisi. 

Il a été intéressant de constater qu'en lançant le script avec cette adresse de broadcast comme adresse cible, cela ne fonctionne pas avec les Reason Codes 1 et 8. Dans ces deux cas, il faut renseigner l'adresse MAC d'une STA en particulier. Ce qui est assez logique pour le code 8 car il est censé venir d'une STA bien précise vers l'AP pour indiquer qu'elle quitte le BSS. Par contre pour ce qui est du code 1, cela est peut-être dû au fait qu'il n'est pas possible de déconnecter toutes les STAs en fournissant une raison non-spécifiée.



__Question__ : Quelle est la différence entre le code 3 et le code 8 de la liste ?

Dans les deux cas, cela indique que la STA quitte le Service Set auquel elle était connectée. Mais la nuance est que le code 3 indique qu'elle a quitté le Service Set IBSS (Independant Basic Service Set) ou le Service Set ESS (Extended Service Set) alors que le code 8 indique qu'elle a quitté le Service Set BSS (Basic Service Set).

Caractéristiques de ces 3 modes d'opération : 

- **IBSS** : Réseau sans-fil n'utilisant pas de point d'accès et n’étant constitué que d’équipements clients qui communiquent entre eux sans aucune fonction de contrôle, de gestion de la sécurité ou de statistique centralisée. Réseau "ad-hoc" ou "peer-to-peer".
- **ESS** : Réseau sans fil, créé par plusieurs points d'accès, qui apparaît aux utilisateurs comme un réseau unique et homogène, tel qu'un réseau couvrant une maison ou un bureau qui est trop grand pour être couvert de manière fiable par un seul point d'accès. Les points d'accès sont reliés entre eux par un DS (Distribution System).
- **BSS** : Réseau sans-fil classique que l'on trouve dans la majorité des cas, identifié par un BSSID, formé par un AP et les stations situées dans sa zone de couverture.



__Question__ : Expliquer l'effet de cette attaque sur la cible

La cible est directement déconnectée du réseau et perd donc l'accès à Internet tant que les trames de désauthentification lui sont envoyées. Elle tente donc de se connecter à un autre réseau pouvant lui fournir un accès.

Il a été intéressant de voir que si l'on envoie suffisamment de trames de désauthentification à une STA cible, elle met un certain temps à se reconnecter au réseau, il a même été des fois nécessaire de la reconnecter manuellement après l'attaque.



Le script demande d'entrer l'adresse MAC cible, le BSSID de l'AP auquel la cible est connectée (ici on souhaite déconnecter tout le monde du réseau) puis d'entrer un Reason Code et envoie finalement les trames de désauthentification : 

![image-20220329180055800](figures/image-20220329180055800.png)



### 2. Fake channel evil tween attack
a)	Développer un script en Python/Scapy avec les fonctionnalités suivantes :

* Dresser une liste des SSID disponibles à proximité
* Présenter à l'utilisateur la liste, avec les numéros de canaux et les puissances
* Permettre à l'utilisateur de choisir le réseau à attaquer
* Générer un beacon concurrent annonçant un réseau sur un canal différent se trouvant à 6 canaux de séparation du réseau original

__Question__ : Expliquer l'effet de cette attaque sur la cible

On annonce avec ces beacons que le réseau est disponible sur un autre canal, la cible peut alors s'y connecter. Elle n'aura cependant pas de connexion sur ce canal car il n'y pas de réseau sur cette fréquence. On pourrait disposer d'un AP malicieux sur ce canal afin de récupérer les informations de la cible qui transitent. Combinée à l'attaque par désauthentification du point précédent, on pourrait dans un premier temps déconnecter la cible puis, dans un deuxième temps, envoyer des beacons forgés afin qu'elle se connecte sur notre réseau malicieux.



Le script demande d'entrer le BSSID du réseau de l'evil twin comme argument, affiche les différents réseaux détectés en fonction des beacons capturés puis propose de se faire passer pour un de ces réseaux en entrant son BSSID. Finalement il envoie des beacons avec le SSID du réseau usurpé sur un canal situé à 6 canaux d'écart du vrai réseau  :

![image-20220329182343676](figures/image-20220329182343676.png)

Exemple d'utilisation du script : 

```bash
sudo python3 evil_twin.py 38:00:25:8E:A4:E5
```




### 3. SSID flood attack

Développer un script en Python/Scapy capable d'inonder la salle avec des SSID dont le nom correspond à une liste contenue dans un fichier text fournit par un utilisateur. Si l'utilisateur ne possède pas une liste, il peut spécifier le nombre d'AP à générer. Dans ce cas, les SSID seront générés de manière aléatoire.

Ici le script génère les beacons de 4 SSIDs aléatoires possédant tous une adresse MAC aléatoire :

![image-20220329200437451](figures/image-20220329200437451.png)

On les voit ensuite apparaître dans une capture Wireshark :

![image-20220329200600581](figures/image-20220329200600581.png)



Par contre ici, le script génère les beacons de 4 SSIDs contenus dans le fichier `ssid_list.txt`  avec également des adresses MAC aléatoires :

![image-20220329201012337](figures/image-20220329201012337.png)

Même chose ici, on peut les voir apparaître dans une capture Wireshark :

![image-20220329201238803](figures/image-20220329201238803.png)




## Partie 2 - probes

## Introduction

L’une des informations de plus intéressantes et utiles que l’on peut obtenir à partir d’un client sans fils de manière entièrement passive (et en clair) se trouve dans la trame ``Probe Request`` :

![Probe Request et Probe Response](images/probes.png)

Dans ce type de trame, utilisée par les clients pour la recherche active de réseaux, on peut retrouver :

* L’adresse physique (MAC) du client (sauf pour dispositifs iOS 8 ou plus récents et des versions plus récentes d'Android). 
	* Utilisant l’adresse physique, on peut faire une hypothèse sur le constructeur du dispositif sans fils utilisé par la cible.
	* Elle peut aussi être utilisée pour identifier la présence de ce même dispositif à des différents endroits géographiques où l’on fait des captures, même si le client ne se connecte pas à un réseau sans fils.
* Des noms de réseaux (SSID) recherchés par le client.
	* Un Probe Request peut être utilisé pour « tracer » les pas d’un client. Si une trame Probe Request annonce le nom du réseau d’un hôtel en particulier, par exemple, ceci est une bonne indication que le client s’est déjà connecté au dit réseau. 
	* Un Probe Request peut être utilisé pour proposer un réseau « evil twin » à la cible.

Il peut être utile, pour des raisons entièrement légitimes et justifiables, de détecter si certains utilisateurs se trouvent dans les parages. Pensez, par exemple, au cas d'un incendie dans un bâtiment. On pourrait dresser une liste des dispositifs et la contraster avec les personnes qui ont déjà quitté le lieu.

A des fins plus discutables du point de vue éthique, la détection de client s'utilise également pour la recherche de marketing. Aux Etats Unis, par exemple, on "sniff" dans les couloirs de centres commerciaux pour détecter quelles vitrines attirent plus de visiteurs, et quelle marque de téléphone ils utilisent. Ce service, interconnecté en réseau, peut aussi déterminer si un client visite plusieurs centres commerciaux un même jour ou sur un certain intervalle de temps.

### 4. Probe Request Evil Twin Attack

Nous allons nous intéresser dans cet exercice à la création d'un evil twin pour viser une cible que l'on découvre dynamiquement utilisant des probes.

Développer un script en Python/Scapy capable de detecter une STA cherchant un SSID particulier - proposer un evil twin si le SSID est trouvé (i.e. McDonalds, Starbucks, etc.).

Pour la détection du SSID, vous devez utiliser Scapy. Pour proposer un evil twin, vous pouvez très probablement réutiliser du code des exercices précédents ou vous servir d'un outil existant.

__Question__ : comment ça se fait que ces trames puissent être lues par tout le monde ? Ne serait-il pas plus judicieux de les chiffrer ?

Cela rendrait plus complexe la recherche de réseaux car cela impliquerait une gestion de clé pour que l'AP ciblé déchiffre la Probe Request avant même que la STA soit authentifiée auprès de lui. De plus, la randomisation des adresses MAC limite déjà correctement l'impact de cette attaque et les STAs envoient moins de Probe Requests qu'à l'époque.



__Question__ : pourquoi les dispositifs iOS et Android récents ne peuvent-ils plus être tracés avec cette méthode ?

Car ils sont capables de randomiser leur adresse MAC et ne peuvent donc plus être identifiés lorsqu'ils envoient une Probe Request afin de trouver un réseau.



Le script requiert le BSSID du réseau de l'evil twin comme argument. Il affiche ensuite les Probe Requests détectées et dans un même temps les réseaux disponibles aux alentours. Puis, il demande à l'utilisateur d'entrer le SSID du réseau qu'il veut usurper. Si le réseau a bien été détecté à proximité, le script va générer des beacons avec son SSID sur un canal situé à 6 canaux d'écart du vrai réseau :

![image-20220329210545514](figures/image-20220329210545514.png)

Exemple d'utilisation :

```bash
sudo python3 probe_attack.py 38:00:25:8E:A4:E5
```




### 5. Détection de clients et réseaux

a) Développer un script en Python/Scapy capable de lister toutes les STA qui cherchent activement un SSID donné

Le script requiert le SSID qui doit être présent dans les Probe Requests comme argument. Puis il affiche les adresses MAC des appareils qui ont fait des Probe Requests demandant le SSID choisi :

![image-20220329214506453](figures/image-20220329214506453.png)

Exemple d'utilisation :

```bash
sudo python3 detecting_sta.py WOW
```



b) Développer un script en Python/Scapy capable de générer une liste d'AP visibles dans la salle et de STA détectés et déterminer quelle STA est associée à quel AP. Par exemple :

STAs &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; APs

B8:17:C2:EB:8F:8F &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 08:EC:F5:28:1A:EF

9C:F3:87:34:3C:CB &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 00:6B:F1:50:48:3A

00:0E:35:C8:B8:66 &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; 08:EC:F5:28:1A:EF

Le script affiche les BSSIDs et SSIDs des APs détectés aux alentours ainsi que les STAs associées à ceux-ci :

![image-20220329222059612](figures/image-20220329222059612.png)

Exemple d'utilisation :

```bash
sudo python3 detecting_associated_sta.py
```




### 6. Hidden SSID reveal (exercices challenge optionnel - donne droit à un bonus)

Développer un script en Python/Scapy capable de reveler le SSID correspondant à un réseau configuré comme étant "invisible".

__Question__ : expliquer en quelques mots la solution que vous avez trouvée pour ce problème ?

Un réseau masqué remplace les caractères de son SSID dans les beacons par des bytes `\x00`. Nous avons donc commencé par capturer les beacons des réseaux masqués. Puis, pour trouver leurs vrais SSIDs, nous avons sniffé le réseau jusqu'à capturer des Probe Responses envoyées par ces mêmes réseaux masqués contenant leurs SSIDs réels.

Le script détecte tout d'abord les beacons envoyés par les réseaux cachés :

![image-20220330093955315](figures/image-20220330093955315.png)

Puis, lorsqu'il capture des Probe Responses, il affiche le SSID du réseau masqué et son BSSID associé :

![image-20220330094127794](figures/image-20220330094127794.png)

Dans un même temps, il met à jour le tableau avec le SSID révélé :

![image-20220330094047473](figures/image-20220330094047473.png)

Exemple d'utilisation :

```bash
sudo python3 reveal_hidden_ssid.py -s 10000
```

Ici l'option `-s` permet de renseigner une durée (en secondes) pendant lequel le script va sniffer le réseau.



## Livrables

Un fork du repo original . Puis, un Pull Request contenant :

- Script de Deauthentication de clients 802.11 __abondamment commenté/documenté__

- Script fake chanel __abondamment commenté/documenté__

- Script SSID flood __abondamment commenté/documenté__

- Script evil twin __abondamment commenté/documenté__

- Scripts détection STA et AP __abondamment commenté/documenté__

- Script SSID reveal __abondamment commenté/documenté__


- Captures d'écran du fonctionnement de chaque script

-	Réponses aux éventuelles questions posées dans la donnée. Vous répondez aux questions dans votre ```README.md``` ou dans un pdf séparé

-	Envoyer le hash du commit et votre username GitHub par email au professeur et à l'assistant


## Échéance

Le 31 mars 2022 à 23h59
