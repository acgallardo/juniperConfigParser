#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Vuelca las reglas exportadas del firewall a un base de datos.

History:
0.1

TODO:
    - Procesar interface
    - Procesar service
"""
import ruledb
import shlex
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

juniper_export_file = config['JUNIPER']['file']
db_name = config['DATABASE']['file']
csv_filename = config['CSV']['file']

stats = {
    'address': 0,
    'gaddress': 0,
    'policy': 0,
    'src_address': 0,
    'dst_address': 0
    }

last_rule = 0
unprocessed = []


def procesa_address(db, cadena):
    """
    Procesa e inserta las direcciones en la base de datos.

    Posiciones:
    [0] set
    [1] address
    [2] zona
    [3] etiqueta
    [4] ip
    [5] mascara
    [6] comentario
    """
    datos = shlex.split(cadena)

    # WTF! El firewall permite incluir direcciones raritas:
    # set address "Trust" "1" 1
    if len(datos) >= 6:
        comentario = ''

        ip = datos[4]
        mascara = datos[5]
        zona = datos[2]
        etiqueta = datos[3]

        if len(datos) == 7:
            comentario = datos[6]

        db.add_ip(ip, mascara, zona, etiqueta, comentario)
        stats['address'] += 1
    else:
        if config['JUNIPER']['dump_unprocessed']:
            unprocessed.append(cadena)


def procesa_group_address(db, cadena):
    """
    Procesa e inserta grupos de direcciones en la base de datos.

    Posiciones:
    [0] set
    [1] group
    [2] address
    [3] zona
    [4] nombre
    [5] comment / add
    [6] comentario / etiqueta de ip
    """
    datos = shlex.split(cadena)

    if(len(datos) == 5 or datos[5] == "comment"):

        nombre = datos[4]
        zona = datos[3]

        db.grupo_add(nombre, zona)

    elif(len(datos) > 6 and datos[5] != "comment"):

        id_ip = db.get_ip_id(datos[6])

        id_grupo = db.get_id_grupo(datos[4])

        db.grupo_ip_add(id_grupo, id_ip)

    stats['gaddress'] += 1


def procesa_policy(db, cadena):
    """
    Procesa e inserta políticas en la base de datos.

    Posiciones:
    longitudes 13,14,15,17
    [0] set
    [1] policy
    [2] id
    [3] id_politica
    [4] name                    | from
    [5] nombre                  | zona
    [6] from                    | to
    [7] zona                    | zona
    [8] to                      | etiqueta ip / grupo ip
    [9] zona                    | etiqueta ip / grupo ip
    [10] etiqueta ip / grupo ip | puertos
    [11] etiqueta ip / grupo ip | permit / deny
    [12] puertos                | log
    [13] permit / deny          | --
    [14] log                    | --
    """
    datos = shlex.split(cadena)

    regla = {
        'id': 0,
        'nombre': '',
        'from_zona': '',
        'to_zona': '',
        'ip_from': '',
        'ip_dst': '',
        'tipo': '',
        'log': 0,
        'nat': 0,
        'src': 0,
        'count': 0
    }

    # regla deshabilitada
    if len(datos) == 5:
        db.regla_enabled(datos[3], 0)
    elif len(datos) > 5:
        # regla con nombre
        if datos[4] == 'name':
            # print(cadena)
            regla['id'] = datos[3]
            regla['nombre'] = datos[5]
            regla['from_zona'] = datos[7]
            regla['to_zona'] = datos[9]
            regla['ip_from'] = datos[10]
            regla['ip_dst'] = datos[11]
            regla['protocolo'] = datos[12]
            regla['tipo'] = datos[13]
        # regla sin nombre
        else:
            regla['id'] = datos[3]
            regla['nombre'] = ''
            regla['from_zona'] = datos[5]
            regla['to_zona'] = datos[7]
            regla['ip_from'] = datos[8]
            regla['ip_dst'] = datos[9]
            regla['protocolo'] = datos[10]
            # regla['tipo'] = datos[11]

        if 'deny' in datos:
            regla['tipo'] = 'deny'
        elif 'permit' in datos:
            regla['tipo'] = 'permit'

        if 'log' in datos:
            regla['log'] = 1

        if 'nat' in datos:
            regla['nat'] = 1

        if 'src' in datos:
            regla['src'] = 1

        if 'count' in datos:
            regla['count'] = 1

        # Insertamos la regla
        db.regla_add(regla['id'],
                     regla['nombre'],
                     regla['from_zona'],
                     regla['to_zona'],
                     regla['tipo'],
                     regla['log'],
                     regla['nat'],
                     regla['src'],
                     regla['count'])

        source = db.get_ip_id(regla['ip_from'])

        if source is not False:
            db.regla_ip_add(regla['id'], source, 'src')
        else:
            id_grupo = db.get_id_grupo(regla['ip_from'])

            if(id_grupo is not False):
                db.regla_group_add(regla['id'], id_grupo, 'src')

        destination = db.get_ip_id(regla['ip_dst'])

        if destination is not False:
            db.regla_ip_add(regla['id'], destination, 'dst')
        else:
            id_grupo = db.get_id_grupo(regla['ip_dst'])

            if(id_grupo is not False):
                db.regla_group_add(regla['id'], id_grupo, 'dst')
        stats['policy'] += 1
    else:
        # stoprint(cadena)
        pass

    return datos[3]


def procesa_source_address(db, cadena, last_rule):
    """Procesa las líneas de configuración que empiezan por source."""
    datos = shlex.split(cadena)

    source = db.get_ip_id(datos[2])

    if source is not False:
        db.regla_ip_add(last_rule, source, 'src')
    else:
        id_grupo = db.get_id_grupo(datos[2])

        if(id_grupo is not False):
            db.regla_group_add(last_rule, id_grupo, 'src')
        else:
            if config['JUNIPER']['dump_unprocessed']:
                unprocessed.append(cadena)

    stats['src_address'] += 1


def procesa_destination_address(db, cadena, last_rule):
    """Procesa las líneas de configuración que empiezan por destination."""
    datos = shlex.split(cadena)

    source = db.get_ip_id(datos[2])

    if source is not False:
        db.regla_ip_add(last_rule, source, 'dst')
    else:
        id_grupo = db.get_id_grupo(datos[2])

        if(id_grupo is not False):
            db.regla_group_add(last_rule, id_grupo, 'dst')
        else:
            if config['JUNIPER']['dump_unprocessed']:
                unprocessed.append(cadena)

    stats['dst_address'] += 1


def main():
    """Main."""
    db = ruledb.Ruledb(db_name)
    configuracion = open(juniper_export_file, mode="r", encoding="latin-1")

    for linea in configuracion:
        if linea.startswith("set address"):

            procesa_address(db, linea)

        elif linea.startswith("set group address"):

            procesa_group_address(db, linea)

        elif linea.startswith("set policy"):

            last_rule = procesa_policy(db, linea)

        elif linea.startswith("set src-address"):

            procesa_source_address(db, linea, last_rule)

        elif linea.startswith("set dst-address"):

            procesa_destination_address(db, linea, last_rule)

        else:
            if config['JUNIPER']['dump_unprocessed']:
                unprocessed.append(linea)

    print("Direcciones procesadas:......" + str(stats['address']))
    print("Grupos procesados:..........." + str(stats['gaddress']))
    print("Reglas procesadas:..........." + str(stats['policy']))
    print("Origenes añadidos a reglas:.." + str(stats['src_address']))
    print("Destinos añadidos a reglas:.." + str(stats['dst_address']))

    if config['CSV']['export_csv']:
        db.dump_to_csv(config['CSV']['file'])

    if config['JUNIPER']['dump_unprocessed']:
        with open(config['JUNIPER']['unprocessed_file'],
                  mode='wt', encoding='utf-8') as noprocess:
            noprocess.write('\n'.join(unprocessed))

if __name__ == '__main__':
    main()
