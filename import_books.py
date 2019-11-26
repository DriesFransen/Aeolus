import os
import csv

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker


def main():
	engine = create_engine(os.getenv("DATABASE_URL"))
	db = scoped_session(sessionmaker(bind=engine))
	with open("books.csv") as f:
		reader = csv.reader(f)
		reader.__next__()
		for isbn, title, author, year in reader:
			db.execute("INSERT INTO books (isbn, title, author, year) VALUES (:isbn, :title, :author, :year)", 
				{"isbn": isbn, "title": title, "author": author, "year": int(year)})
			db.commit()

if __name__ == '__main__':
	main()