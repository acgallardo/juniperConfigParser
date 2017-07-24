#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Base de datos para reglas del firewall juniper.

History:
0.1 plantilla inicial

"""
import sqlite3
import csv


class Ruledb(object):
    """Clase que maneja la base de datos de reglas."""

    def __init__(self, database):
        self.database = database
        self._init_db()

    def _init_db(self):
        self.db = sqlite3.connect(self.database)

        self.cursor = self.db.cursor()

        self.cursor.execute('''DROP TABLE IF EXISTS direcciones_ip ''')
        self.cursor.execute('''DROP TABLE IF EXISTS grupos''')
        self.cursor.execute('''DROP TABLE IF EXISTS grupo_ip''')
        self.cursor.execute('''DROP TABLE IF EXISTS reglas''')
        self.cursor.execute('''DROP TABLE IF EXISTS regla_ip''')
        self.cursor.execute('''DROP VIEW IF EXISTS src''')
        self.cursor.execute('''DROP VIEW IF EXISTS dst''')
        self.cursor.execute('''DROP VIEW IF EXISTS vip_src_dst''')
        self.cursor.execute('''DROP VIEW IF EXISTS vrules''')

        self.db.commit()

        self.cursor.execute(
            '''
            CREATE TABLE "direcciones_ip" (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "ip" TEXT,
                "mascara" TEXT,
                "zona" TEXT,
                "etiqueta" TEXT,
                "comentario" TEXT)
            ''')

        self.cursor.execute('''
            CREATE TABLE "grupos" (
                "id_grupo" INTEGER PRIMARY KEY AUTOINCREMENT,
                "nombre" TEXT,
                "zona" TEXT)
            ''')

        self.cursor.execute('''
            CREATE TABLE "grupo_ip" (
                "id_grupo" INTEGER,
                "id_ip" INTEGER)
            ''')

        self.cursor.execute('''
            CREATE TABLE "reglas" (
                "id" INTEGER PRIMARY KEY,
                "nombre" TEXT,
                "from_zone" TEXT,
                "to_zone" TEXT,
                "tipo" TEXT,
                "log" INTEGER DEFAULT 0,
                "nat" INTEGER DEFAULT 0,
                "src" INTEGER DEFAULT 0,
                "count" INTEGER DEFAULT 0,
                "enable" INTEGER DEFAULT 1)
            ''')

        self.cursor.execute('''
            CREATE TABLE regla_ip (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "id_regla" INTEGER,
                "id_ip" INTEGER,
                "tipo" TEXT)
            ''')

        self.cursor.execute('''
            CREATE VIEW src AS
            SELECT id_regla, id_ip, ip, etiqueta
            FROM regla_ip
            JOIN direcciones_ip
                ON regla_ip.id_ip = direcciones_ip.id
            WHERE tipo = 'src'
            ''')
        self.cursor.execute('''
            CREATE VIEW dst AS
            SELECT id_regla, id_ip, ip, etiqueta
            FROM regla_ip
            JOIN direcciones_ip
                ON regla_ip.id_ip = direcciones_ip.id
            WHERE tipo = 'dst'
            ''')
        self.cursor.execute('''
            CREATE VIEW vip_src_dst AS
                SELECT src.id_regla AS id_regla,
                    src.ip AS src_ip,
                    src.etiqueta as src_etiqueta,
                    dst.ip as dst_ip,
                    src.etiqueta as dst_etiqueta
                from src JOIN dst on src.id_regla = dst.id_regla
            ''')

        self.cursor.execute('''
            CREATE VIEW vrules AS
                SELECT id, nombre, from_zone, to_zone, src_ip,
                    src_etiqueta, dst_ip, dst_etiqueta, tipo,
                    log, nat, src, count, enable
                FROM reglas
                JOIN vip_src_dst
                    ON reglas.id = vip_src_dst.id_regla
            ''')

        # Necesitamos el Any
        self.cursor.execute('''
            INSERT INTO direcciones_ip (ip, mascara, etiqueta)
                VALUES ('0.0.0.0', '0', 'Any')
            ''')

        self.db.commit()

    def add_ip(self, ip, mascara, zona, etiqueta, comentario):
        """Añade una IP."""
        self.cursor.execute('''
            INSERT INTO direcciones_ip(ip, mascara, zona, etiqueta, comentario)
                VALUES(?,?,?,?,?)
            ''', (ip, mascara, zona, etiqueta, comentario))

    def grupo_add(self, nombre, zona):
        """Añade un grupo."""
        self.cursor.execute('''
            INSERT INTO grupos(nombre  , zona)
                VALUES(?,?)
            ''', (nombre, zona))

    def grupo_ip_add(self, grupo, ip):
        """Asigna una ip a un grupo."""
        self.cursor.execute('''
            INSERT INTO grupo_ip
                VALUES(?, ?)
            ''', (grupo, ip))

    def get_id_grupo(self, etiqueta):
        """Devuelve el identificador de un grupo a partir de su etiqueta."""
        self.cursor.execute('''
            SELECT id_grupo from grupos
                WHERE nombre = ?
            ''', (etiqueta,))

        datos = self.cursor.fetchone()

        if datos is not None:
            id_grupo = datos[0]
        else:
            id_grupo = False

        return id_grupo

    def get_ip_id(self, etiqueta):
        """Devuelve el identificador de una ip a partir de su etiqueta."""
        self.cursor.execute('''
            SELECT id FROM direcciones_ip
                WHERE etiqueta = ?
            ''', (etiqueta,))

        datos = self.cursor.fetchone()

        if datos is not None:
            id_ip = datos[0]
        else:
            id_ip = False

        return id_ip

    def regla_add(self, id_regla, nombre, from_zone, to_zone,
                  tipo, log, nat, src, count):
        """Añade una regla."""
        self.cursor.execute('''
            INSERT INTO reglas(id, nombre, from_zone, to_zone,tipo ,
                               log, nat, src, count)
                values(?,?,?,?,?,?,?,?,?)
        ''', (id_regla, nombre, from_zone, to_zone, tipo,
              log, nat, src, count))

    def regla_enabled(self, id, valor):
        """Establece si la regla esta o no deshabilitada."""
        self.cursor.execute('''
            UPDATE reglas
                SET enable = ?
                WHERE id= ?
        ''', (valor, id))

    def regla_group_add(self, id_regla, id_grp, srcdst):
        """
        Asigna todas las ip del grupo indicado a la regla.

        Args:
        id_regla -- Identificador de la regla
        id_grp -- Identificador del grupo
        srcdst -- Idica si la asignacion es a origen(src) o destino(dst)
        """
        self.cursor.execute('''
            SELECT id_ip FROM grupo_ip WHERE id_grupo = ?
        ''', (id_grp,))

        ips = self.cursor.fetchall()

        for ip in ips:
            self.regla_ip_add(id_regla, ip[0], srcdst)

    def regla_ip_add(self, id_regla, id_ip, srcdst):
        """Asigna una ip a una regla."""
        if(srcdst == 'src'):
            tipo = 'src'

        else:
            tipo = 'dst'

        self.cursor.execute('''
            INSERT INTO regla_ip(id_regla, id_ip, tipo)
                VALUES(?,?,?)
        ''', (id_regla, id_ip, tipo))

    def dump_to_csv(self, archivo):
        """Vuelca la base de datos a un fichero csv."""
        cabecera = [
            'id',
            'nombre',
            'from zone',
            'to zone',
            'source ip',
            'source full',
            'destination ip',
            'destination full',
            'type',
            'log',
            'nat',
            'src',
            'count',
            'enable'
            ]

        self.cursor.execute('''
            SELECT * FROM vrules
        ''')

        data = self.cursor.fetchall()

        with open(archivo, 'w', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(cabecera)
            writer.writerows(data)

    def __del__(self):
        self.db.commit()
        self.db.close()


def main():
    """Main."""
    pass

if __name__ == '__main__':
    main()
