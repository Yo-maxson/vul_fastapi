from sqlalchemy import ForeignKey, text, Text, Integer
from sqlalchemy.orm import relationship, Mapped, mapped_column
from app.database import Base, str_uniq, int_pk, str_null_true
from datetime import date

from datetime import datetime


class Cve(Base):

    id: Mapped[int_pk]
    name: Mapped[str_uniq]
    baseScore: Mapped[float]
    vectorString_v3: Mapped[str]
    link: Mapped[str_uniq]
    # bdu_link: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_id: Mapped[int] = mapped_column(Integer, ForeignKey("cwes.id"), nullable=True)

    cwe: Mapped["Cwe"] = relationship("Cwe", back_populates="cves")
    # publicated = Column(Date, default=datetime.utcnow)
    datePublished: Mapped[date]
    dateUpdated: Mapped[date]

    def __str__(self):
        return f"{self.__class__.__name__}(id={self.id})"

    def __repr__(self):
        return str(self)


class Cwe(Base):

    id: Mapped[int_pk]
    # cves: Mapped[list['Cve']] = relationship(
    #     "Cve",
    #     back_populates="cve",
    #     cascade="all, delete",
    # )
    cwe_name: Mapped[str_uniq]
    desc_eng: Mapped[str]

    def __str__(self):
        return f"{self.__class__.__name__}(id={self.id}, cwe_name={self.cwe_name!r})"

    def __repr__(self):
        return str(self)

