from Crypto.Util.number import *

e1 =  28720970875923431651096339432854172528258265954461865674640550905460254396153781189674547341687577425387833579798322688436040388359600753225864838008717449960738481507237546818409576080342018413998438508242156786918906491731633276138883100372823397583184685654971806498370497526719232024164841910708290088581
e2 =  131021266002802786854388653080729140273443902141665778170604465113620346076511262124829371838724811039714548987535108721308165699613894661841484523537507024099679248417817366537529114819815251239300463529072042548335699747397368129995809673969216724195536938971493436488732311727298655252602350061303755611563
N =  159077408219654697980513139040067154659570696914750036579069691821723381989448459903137588324720148582015228465959976312274055844998506120677137485805781117564072817251103154968492955749973403646311198170703330345340987100788144707482536112028286039187104750378366564167383729662815980782817121382587188922253
flag = b"flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}"
f1 = bytes_to_long(flag[:21])
f2 = bytes_to_long(flag[21:])
c1 = pow(f1, e1, N)
c2 = pow(f2, e2, N)

print("e1 = ", e1)
print("e2 = ", e2)
print("N = ", N)
print("c1 = ", c1)
print("c2 = ", c2)


from Crypto.Util.number import getPrime, bytes_to_long
import gmpy2
from secret import hint,flag

assert len(hint)==28

p, q = getPrime(1024), getPrime(1024)
N = p * q
# N = 17919584345306773018250341151907940471878342032767554777059134719728873514659570826793690035196966315710856522947232389386826868369798633208885707032628062730092268104330867495145614701247319287455290884236957679463764604587945278851853171744530901001743245364827898957560335262535932237980799249518493637308410256722396896178338217607523137033516145483686593860177910621944747227504080004840902792379769687077482677422789017549391579034871045742902124870675679997317704847436703294366189863130813107068622648834595237769403500006149462802467063207534750369850057260017680098485695416243056569110099636954503508734293L
lam = gmpy2.lcm(p-1, q-1)
d1, d2 = getPrime(700), getPrime(700)
e1, e2 = gmpy2.invert(d1, lam), gmpy2.invert(d2, lam)
# e1 = 4921085498213645009643791206847399266365422464783372435330809311227326259638403479462666113486039300185780952021008133853874338800942395376308842764738198990850314389886172972543474608522256459370136711911437249457149129984034415658597242836864932883689157943028344715042197534111916160886137075561331213593625931727241927155382389561361325088576127306081599397211320132420081345402962498126401428887258206247294844493214354219193379189655512995321446164370680410657480975629416722239985710866399850526353313948023350511184726024167203456965068437844858569193654417676148528073247312385045311443511589844419388531249L
# e2 = 6955369141332976279089671792055191329971231476947859409227311005832361730248877469951764903475984185465709504555959320881668660051418657895415352037377006360628365934886611325811226300552107299950280121925295919443662764100709028797312744290252466193623119216268229638312832731996012878361358183996369206152582073292642860394385771547995751155911351834488716787219102597028746864808162939025474492314940985181124093294546511443761422924105605380522349827470621491593317823153733975297706094329287269833122413331296702510897395210366309216535116052360978068061258957904006417442341115733800377093210149623921722875823L
m = bytes_to_long(flag)
c = pow(m, 65537, N)
# c = 14541044453539649752238888389031665467568625351308390968353139184145260069441217440017438642663050774420371254250433734968306979295355667236528603475401806039910059500117278000628935344908437749585552760727454814700569506165519718112231135164013951164799583029754442006538670105427307546951196381034571635188078550660041739848296193488219034967888835605802347384423242270704804959920285362970575135361416453247344819439438460567503479757065847455733963066247159912164894258288525184222955154837043451361626357155282358220639312489745340558929263127932262693306438348012181706137969024701745277384961917038968828569532L



#p1, q1 = getPrime(1024), getPrime(1024)
#N1 = p1 * q1
#p0 = p1 ^ (bytes_to_long(hint)<<444)
#assert N1==22752894188316360092540975721906836497991847739424447868959786578153887300450204451741779348632585992639813683087014583667437383610183725778340014971884694702424840759289252997193997614461702362265455177683286566007629947557111478254578643051667900283702126832059297887141543875571396701604215946728406574474496523342528156416445367009267837915658813685925782997542357007012092288854590169727090121416037455857985211971777796742820802720844285182550822546485833511721384166383556717318973404935286135274368441649494487024480611465888320197131493458343887388661805459986546580104914535886977559349182684565216141697843L
#assert p0==165268930359949857026074503377557908247892339573941373503738312676595180929705525120390798235341002232499096629250002305840384250879180463692771724228098578839654230711801010511101603925719055251331144950208399022480638167824839670035053131870941541955431984347563680229468562579668449565647313503239028017367L



#!/usr/local/bin/sage -python
from sage.all import *
from Crypto.Util.number import long_to_bytes
import gmpy2


N1 = 22752894188316360092540975721906836497991847739424447868959786578153887300450204451741779348632585992639813683087014583667437383610183725778340014971884694702424840759289252997193997614461702362265455177683286566007629947557111478254578643051667900283702126832059297887141543875571396701604215946728406574474496523342528156416445367009267837915658813685925782997542357007012092288854590169727090121416037455857985211971777796742820802720844285182550822546485833511721384166383556717318973404935286135274368441649494487024480611465888320197131493458343887388661805459986546580104914535886977559349182684565216141697843
p0 = 165268930359949857026074503377557908247892339573941373503738312676595180929705525120390798235341002232499096629250002305840384250879180463692771724228098578839654230711801010511101603925719055251331144950208399022480638167824839670035053131870941541955431984347563680229468562579668449565647313503239028017367L
# Different parameters for each team
N = 21449895719826316652446571946981952001870566997635249354839719104586793422147136850745824964669880149217071660375357131860682282796961273035757913027221984662855086934378108862417739678560641256025021177459341664799202908015371506818482697948776860635401930560813387486994329880316276005206046676604369818653109492798511157267685062757615124902736832428778894091595763452172598515654092085157566254905703036750059426372678012021690115369113601765685996153603249713637184151546264425226874180985930269362876845015270912918849008772950078638461376666258348157307814840090503490728994671500681702766815576953787813978261
e1 = 154876861410030193905637296965209391737518615267603515377282161163927291285967965497209788803884091512203071770629845496583933653022795932154979438702329298506942119286672966860218225280626597363420844895229952830077688654634909597435821159150203935892844897371875699700527646518533561853297444882053983227593488765684563676352563626896826395039059975553220690136832152388058883795799274080376167383757159656303732365134738082284498670076819991548527840704114978992615193815662908944493989239004523225764813567930483040425975604255002646785221221878939420219915361396619167751523362930788604016988652824182040859853
e2 = 402990417892531977850271294939175215561881274701367217938141276378027299932263277333257773304557909966758931404723788571151364295341508924840669170504985457120360059297598604537100046622550945605718236227573083837228605402001910225151380616962871923554321544941879414420770210243790557120014475150848993651449636282584509883109795086026235707304394495245201159365863786851663410631339564797425347542642297764418117149471025357391362626205617684148715868071334593025123520727806776519925478240637301296453177836917692916152818769174676318043128314246927769799960281108858830520315473333109470979129926160732972172081
c = 21037638775241935705441169753441969181214988969805330775013543248627632552311198450678114235819562675518919466977321520345880402152065754456138008928612618730995007509860931974158286638375767596664571588900873546529219194178268112698039853957041774843749061288696704191382908696861582667493389648259168539280602684104107043926115007135814623174879703368347247535365452080470946340175647350659950178146229633608967125085585415972497659100238875587736956198682668140956431794164348384880775647438732698709407480919045992477653549924142632962331437675488780736097081752111600358026119501809787360220615860538667734006333


_p = p0 - (p0&(2**668-2**444))
PR = PolynomialRing(Zmod(N1), 'x')
x = PR.gen()
f = 2**444 * x + _p
f = f.monic()
r = f.small_roots(X=2**224, beta=0.5)
p1 = ZZ(_p + r[0]*2**444)
hint = ( p1.__xor__(p0) )>>444
print 'hint: ' + long_to_bytes(hint)


alpha2 = 700./2048
M1 = int(gmpy2.mpz(N)**0.5)
M2 = int( gmpy2.mpz(N)**(1+alpha2) )
D = diagonal_matrix(ZZ, [N, M1, M2, 1])
B = Matrix(ZZ, [ [1, -N,   0,  N**2],
                 [0, e1, -e1, -e1*N],
                 [0,  0,  e2, -e2*N],
                 [0,  0,   0, e1*e2] ]) * D

L = B.LLL()

v = Matrix(ZZ, L[0])
x = v * B**(-1)
phi = (x[0,1]/x[0,0]*e1).floor()

PR = PolynomialRing(ZZ, 'x')
x = PR.gen()
f = x**2 - (N-phi+1)*x + N
p, q = f.roots()[0][0], f.roots()[1][0]

d = inverse_mod( 65537, (p-1)*(q-1) )
m = power_mod(c, d, N)
print 'flag: ' + long_to_bytes(m)