﻿// <auto-generated />
using System;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace PermissionAppNew.Migrations
{
    [DbContext(typeof(DataContext))]
    [Migration("20241222172419_InitialCreate")]
    partial class InitialCreate
    {
        /// <inheritdoc />
        protected override void BuildTargetModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "8.0.10");

            modelBuilder.Entity("Admin", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("Email")
                        .HasColumnType("TEXT");

                    b.Property<string>("Name")
                        .HasColumnType("TEXT");

                    b.Property<string>("NickName")
                        .HasColumnType("TEXT");

                    b.Property<string>("Password")
                        .HasColumnType("TEXT");

                    b.Property<string>("SurName")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("Admins");
                });

            modelBuilder.Entity("Duyuru", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int?>("AdminId")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("DuyuruTarih")
                        .HasColumnType("TEXT");

                    b.Property<string>("Icerik")
                        .HasColumnType("TEXT");

                    b.Property<string>("Konu")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.HasIndex("AdminId");

                    b.ToTable("Duyurus");
                });

            modelBuilder.Entity("Intern", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("Age")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.Property<string>("NickName")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.Property<string>("Okul")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Phone")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Position")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.Property<string>("SurName")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("stajBaslama")
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("stajBitis")
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("Interns");
                });

            modelBuilder.Entity("LeaveDay", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int?>("AdminId")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("EndDate")
                        .HasColumnType("TEXT");

                    b.Property<int?>("InternId")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("IzinAlimTarihi")
                        .HasColumnType("TEXT");

                    b.Property<string>("IzinOnayDurumu")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("LeaveType")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<DateTime>("StartDate")
                        .HasColumnType("TEXT");

                    b.Property<int?>("UserId")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("AdminId");

                    b.HasIndex("InternId");

                    b.HasIndex("UserId");

                    b.ToTable("LeaveDays");
                });

            modelBuilder.Entity("Log", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<string>("Action")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int?>("AdminId")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Description")
                        .HasColumnType("TEXT");

                    b.Property<int?>("InternId")
                        .HasColumnType("INTEGER");

                    b.Property<int?>("LeaveDayId")
                        .HasColumnType("INTEGER");

                    b.Property<DateTime>("Timestamp")
                        .HasColumnType("TEXT");

                    b.Property<int?>("UserId")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("AdminId");

                    b.HasIndex("InternId");

                    b.HasIndex("LeaveDayId");

                    b.HasIndex("UserId");

                    b.ToTable("Logs");
                });

            modelBuilder.Entity("User", b =>
                {
                    b.Property<int>("Id")
                        .ValueGeneratedOnAdd()
                        .HasColumnType("INTEGER");

                    b.Property<int>("Age")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Email")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.Property<string>("NickName")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.Property<string>("Password")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Phone")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("Position")
                        .IsRequired()
                        .HasMaxLength(50)
                        .HasColumnType("TEXT");

                    b.Property<string>("SurName")
                        .IsRequired()
                        .HasMaxLength(100)
                        .HasColumnType("TEXT");

                    b.HasKey("Id");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("Duyuru", b =>
                {
                    b.HasOne("Admin", "Admins")
                        .WithMany("Duyurus")
                        .HasForeignKey("AdminId");

                    b.Navigation("Admins");
                });

            modelBuilder.Entity("LeaveDay", b =>
                {
                    b.HasOne("Admin", "Admins")
                        .WithMany("LeaveDays")
                        .HasForeignKey("AdminId");

                    b.HasOne("Intern", "Interns")
                        .WithMany("LeaveDays")
                        .HasForeignKey("InternId");

                    b.HasOne("User", "Users")
                        .WithMany("LeaveDays")
                        .HasForeignKey("UserId");

                    b.Navigation("Admins");

                    b.Navigation("Interns");

                    b.Navigation("Users");
                });

            modelBuilder.Entity("Log", b =>
                {
                    b.HasOne("Admin", "Admins")
                        .WithMany("Logs")
                        .HasForeignKey("AdminId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("Intern", "Interns")
                        .WithMany("Logs")
                        .HasForeignKey("InternId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("LeaveDay", "LeaveDays")
                        .WithMany("Logs")
                        .HasForeignKey("LeaveDayId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.HasOne("User", "Users")
                        .WithMany("Logs")
                        .HasForeignKey("UserId")
                        .OnDelete(DeleteBehavior.Restrict);

                    b.Navigation("Admins");

                    b.Navigation("Interns");

                    b.Navigation("LeaveDays");

                    b.Navigation("Users");
                });

            modelBuilder.Entity("Admin", b =>
                {
                    b.Navigation("Duyurus");

                    b.Navigation("LeaveDays");

                    b.Navigation("Logs");
                });

            modelBuilder.Entity("Intern", b =>
                {
                    b.Navigation("LeaveDays");

                    b.Navigation("Logs");
                });

            modelBuilder.Entity("LeaveDay", b =>
                {
                    b.Navigation("Logs");
                });

            modelBuilder.Entity("User", b =>
                {
                    b.Navigation("LeaveDays");

                    b.Navigation("Logs");
                });
#pragma warning restore 612, 618
        }
    }
}
